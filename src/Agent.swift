// lembas agent — the local half of "direct first, pool only on limits".
//
// Claude Code points at http://127.0.0.1:<port> with its normal claude.ai login.
// Every request is forwarded straight to api.anthropic.com from this machine. Only
// when Anthropic says that login hit a usage limit does the agent retry through the
// pool. Prompts never go to the pool in the normal path; only metered USD metadata.
//
// Ships inside lembas.app; the app copies it to ~/Library/Application Support/lembas and
// runs it under launchd, so it keeps working when the menu bar app is closed — and even
// after the app is deleted, until it has safely retired (see Lifecycle).

import Foundation

struct AgentConfig: Decodable {
  var url: String
  var token: String
  var agentPort: Int?
  // Borrow over MPC-TLS so the pool can't read the request or the answer (PrivateBorrow.swift).
  var privateBorrowing: Bool?
}

let env = ProcessInfo.processInfo.environment
let home = FileManager.default.homeDirectoryForCurrentUser
// Falls back to the pre-rename (claudus) config until the menu bar app migrates it.
let configPath = env["LEMBAS_AGENT_CONFIG"]
  ?? [".config/lembas.json", ".config/claudus-bar.json"].map { home.appendingPathComponent($0).path }
    .first { FileManager.default.fileExists(atPath: $0) } ?? home.appendingPathComponent(".config/lembas.json").path
let anthropic = env["LEMBAS_AGENT_UPSTREAM"] ?? "https://api.anthropic.com"

// Set in the launchd job by the app: where things live, so the agent can tell when
// lembas was deleted or the pool left, and clean up after itself.
let appPath = env["LEMBAS_APP_PATH"]
let claudeSettingsPath = env["LEMBAS_CLAUDE_SETTINGS"]
let agentLabel = env["LEMBAS_AGENT_LABEL"]
let agentPlistPath = env["LEMBAS_AGENT_PLIST"]
let defaultPort = Int(env["LEMBAS_AGENT_PORT"] ?? "") ?? 8788

// A short default probe interval when Anthropic gives no retry-after: fall back to the
// pool, but try direct again soon instead of locking the native login out for 20 min.
let defaultLimitSeconds = 60.0
let maxLimitSeconds = 6 * 3600.0

let requestHopHeaders: Set<String> = ["host", "connection", "content-length", "accept-encoding", "transfer-encoding", "expect"]
let responseHopHeaders: Set<String> = ["connection", "content-length", "transfer-encoding", "content-encoding", "keep-alive"]

let session: URLSession = {
  let config = URLSessionConfiguration.ephemeral
  config.timeoutIntervalForRequest = 600 // long thinking pauses between stream events
  config.timeoutIntervalForResource = 6 * 3600
  config.httpMaximumConnectionsPerHost = 32
  config.urlCache = nil
  return URLSession(configuration: config)
}()

func log(_ message: String) {
  FileHandle.standardError.write(Data("[agent] \(message)\n".utf8))
}

actor DirectLock {
  private var until = Date.distantPast
  var active: Bool { Date() < until }
  func lock(for seconds: Double) { until = Date().addingTimeInterval(seconds) }
}

// Keeps Claude Code working through every way out of lembas. Once the app is deleted
// or the pool is left, the agent stops using the pool, takes itself out of Claude
// Code's settings (so new sessions talk to Anthropic directly), keeps serving the
// sessions already pointed at it, and removes itself when none of those are left.
actor Lifecycle {
  let port: Int
  private(set) var retiring = false
  private var retiredAt = Date()
  private var lastRequest = Date()
  private var appMissingChecks = 0

  init(port: Int) { self.port = port }

  func touch() { lastRequest = Date() }

  func check() async {
    // An update briefly swaps the app bundle, so require it missing on two checks.
    let appMissing = appPath.map { !FileManager.default.fileExists(atPath: $0) } ?? false
    appMissingChecks = appMissing ? appMissingChecks + 1 : 0
    let configGone = !FileManager.default.fileExists(atPath: configPath)
    if !retiring && (appMissingChecks >= 2 || configGone) {
      retiring = true
      retiredAt = Date()
      log("\(configGone ? "left the pool" : "lembas was deleted"): direct to Anthropic only; retiring once open Claude Code sessions finish")
      removeFromClaudeSettings()
    }
    guard retiring else { return }
    let idle = Date().timeIntervalSince(lastRequest)
    if (idle > 600 && !claudeSessionsStarted(before: retiredAt)) || idle > 24 * 3600 {
      removeSelf()
    }
  }

  // Drops ANTHROPIC_BASE_URL from Claude Code's settings, but only if it still points here.
  private func removeFromClaudeSettings() {
    guard let path = claudeSettingsPath, let data = FileManager.default.contents(atPath: path),
          var settings = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          var envBlock = settings["env"] as? [String: Any],
          envBlock["ANTHROPIC_BASE_URL"] as? String == "http://127.0.0.1:\(port)" else { return }
    envBlock.removeValue(forKey: "ANTHROPIC_BASE_URL")
    if envBlock.isEmpty { settings.removeValue(forKey: "env") } else { settings["env"] = envBlock }
    if let out = try? JSONSerialization.data(withJSONObject: settings, options: [.prettyPrinted, .sortedKeys]) {
      try? out.write(to: URL(fileURLWithPath: path), options: .atomic)
      try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path)
    }
  }

  // Whether a Claude Code process older than `date` is still running: it was started
  // with our address and would break if we left.
  private func claudeSessionsStarted(before date: Date) -> Bool {
    let ps = Process()
    ps.executableURL = URL(fileURLWithPath: "/bin/ps")
    ps.arguments = ["-axo", "etime=,comm="]
    let pipe = Pipe()
    ps.standardOutput = pipe
    guard (try? ps.run()) != nil else { return true } // unsure: keep serving
    let output = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    ps.waitUntilExit()
    for line in output.split(separator: "\n") {
      let parts = line.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: true)
      guard parts.count == 2, parts[1].split(separator: "/").last == "claude" else { continue }
      if Date().addingTimeInterval(-elapsedSeconds(String(parts[0]))) < date { return true }
    }
    return false
  }

  // ps etime: [[dd-]hh:]mm:ss
  private func elapsedSeconds(_ etime: String) -> TimeInterval {
    let dayParts = etime.split(separator: "-")
    let days = dayParts.count == 2 ? Double(dayParts[0]) ?? 0 : 0
    let clock = (dayParts.last ?? "").split(separator: ":").compactMap { Double($0) }
    return days * 86400 + clock.reduce(0) { $0 * 60 + $1 }
  }

  private func removeSelf() {
    log("no Claude Code sessions use lembas anymore; removing the agent")
    if let plist = agentPlistPath { try? FileManager.default.removeItem(atPath: plist) }
    let binary = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    if binary.path.contains("/Application Support/lembas/") {
      try? FileManager.default.removeItem(at: binary.deletingLastPathComponent())
    }
    if let label = agentLabel {
      let launchctl = Process()
      launchctl.executableURL = URL(fileURLWithPath: "/bin/launchctl")
      launchctl.arguments = ["bootout", "gui/\(getuid())/\(label)"] // stops us for good
      try? launchctl.run()
      launchctl.waitUntilExit()
    }
    exit(0)
  }
}

final class Agent {
  let pool: String?
  let poolToken: String
  let directLock = DirectLock()
  let lifecycle: Lifecycle

  // Without a config the agent still forwards straight to Anthropic, so Claude Code
  // keeps working while it retires.
  init(config: AgentConfig?, lifecycle: Lifecycle) {
    pool = config.map { $0.url.hasSuffix("/") ? String($0.url.dropLast()) : $0.url }
    poolToken = config?.token ?? ""
    self.lifecycle = lifecycle
  }

  private func usingPool() async -> Bool {
    let retiring = await lifecycle.retiring
    return pool != nil && !retiring
  }

  func handle(_ req: HTTPRequest, _ out: HTTPResponder) async {
    guard req.path.hasPrefix("/v1/") || req.path.hasPrefix("/api/") else {
      return await out.sendJSON(status: 404, ["type": "error", "error": ["type": "not_found_error", "message": "Not found."]])
    }
    await lifecycle.touch()
    do {
      let model = modelName(req.body)
      let usePool = await usingPool()

      // The native login recently hit a real usage limit: go straight to the pool until
      // the lock expires, then probe direct again. Only inference calls borrow — Claude
      // Code's /api/* account and usage screens always reflect the member's own login.
      let limited = forcePool ? true : await directLock.active
      if usePool, limited, req.path.hasPrefix("/v1/") {
        if await tryPool(req, out) { return }
      }

      let (bytes, upstream) = try await open(upstreamRequest(anthropic, req, poolAuth: false), out)

      if upstream.statusCode != 429 {
        let tap = UsageTap(contentType: upstream.value(forHTTPHeaderField: "content-type"))
        await relay(bytes, upstream, out, tap: tap)
        reportDirectUsage(model: model, usd: costUsd(model: model, usage: tap.finish()))
        return
      }

      var body = Data()
      for try await byte in bytes { body.append(byte) }
      let text = String(decoding: body, as: UTF8.self)
      log("429 from Anthropic: \(describeLimit(upstream, text))")
      if !isUsageLimit(upstream, text) {
        return await sendFixed(out, upstream, body) // transient rate limit: Claude Code retries direct
      }

      if usePool {
        let seconds = retryAfterSeconds(upstream) ?? defaultLimitSeconds
        log("native login hit a usage limit; using the pool for \(Int(seconds))s")
        await tellPoolItIsALimit(seconds: seconds)
        if await tryPool(req, out) { return }
      }
      await sendFixed(out, upstream, body) // pool down/no donors: preserve Anthropic's own error
    } catch {
      log("\(error.localizedDescription)")
      if !out.closed {
        await out.sendJSON(status: 502, ["type": "error", "error": ["type": "api_error", "message": "lembas agent could not reach Anthropic."]])
      }
    }
  }

  // ---------- forwarding ----------

  func upstreamRequest(_ base: String, _ req: HTTPRequest, poolAuth: Bool) -> URLRequest {
    var request = URLRequest(url: URL(string: base + req.path)!)
    request.httpMethod = req.method
    for (name, value) in req.headers where !requestHopHeaders.contains(name) {
      if poolAuth && (name == "authorization" || name == "x-api-key") { continue }
      request.addValue(value, forHTTPHeaderField: name)
    }
    request.setValue("identity", forHTTPHeaderField: "accept-encoding")
    if poolAuth { request.setValue("Bearer \(poolToken)", forHTTPHeaderField: "authorization") }
    if req.method != "GET" && req.method != "HEAD" { request.httpBody = req.body }
    return request
  }

  // Starts the request; it is cancelled if the client disconnects.
  func open(_ request: URLRequest, _ out: HTTPResponder) async throws -> (URLSession.AsyncBytes, HTTPURLResponse) {
    let (bytes, response) = try await session.bytes(for: request)
    out.whenClosed { bytes.task.cancel() }
    guard let http = response as? HTTPURLResponse else { throw URLError(.badServerResponse) }
    return (bytes, http)
  }

  func responseHeaders(_ response: HTTPURLResponse) -> [(String, String)] {
    response.allHeaderFields.compactMap { key, value in
      guard let name = (key as? String)?.lowercased(), !responseHopHeaders.contains(name) else { return nil }
      return (name, "\(value)")
    }
  }

  // Streams the body through, flushing at each line so SSE events arrive immediately.
  func relay(_ bytes: URLSession.AsyncBytes, _ response: HTTPURLResponse, _ out: HTTPResponder, tap: UsageTap? = nil) async {
    await out.start(status: response.statusCode, headers: responseHeaders(response))
    var pending = Data()
    do {
      for try await byte in bytes {
        pending.append(byte)
        if byte == 0x0A || pending.count >= 16 << 10 {
          tap?.push(pending)
          guard await out.chunk(pending) else { bytes.task.cancel(); return }
          pending.removeAll(keepingCapacity: true)
        }
      }
    } catch {
      if !out.closed { log("upstream stream ended early: \(error.localizedDescription)") }
    }
    tap?.push(pending)
    await out.chunk(pending)
    await out.end()
  }

  func sendFixed(_ out: HTTPResponder, _ response: HTTPURLResponse, _ body: Data) async {
    await out.send(status: response.statusCode, headers: responseHeaders(response), body: body)
  }

  func tryPool(_ req: HTTPRequest, _ out: HTTPResponder) async -> Bool {
    guard let pool else { return false }
    // Borrowing is private wherever the pool can lend privately; the relay the pool
    // can read is used only when the pool itself says it has no helper. Any failure
    // of the private path pauses borrowing instead (Claude Code gets Anthropic's own
    // limit error). `privateBorrowing: false` in the config is an escape hatch, not in
    // the app's UI, that forces the relay.
    if currentConfig()?.privateBorrowing != false {
      switch await tryPrivate(req, out) {
      case .served: return true
      case .unsupported: break // no helper at the pool: the relay it is
      case .failed: return false
      }
    }
    do {
      let (bytes, upstream) = try await open(upstreamRequest(pool, req, poolAuth: true), out)
      await relay(bytes, upstream, out)
      return true
    } catch {
      log("pool fallback unavailable: \(error.localizedDescription)")
      return false
    }
  }

  // ---------- talking to the pool: metadata only ----------

  func poolPut(_ path: String, _ body: [String: Any]) async throws {
    guard let pool else { return }
    var request = URLRequest(url: URL(string: pool + path)!)
    request.httpMethod = "PUT"
    request.timeoutInterval = 3
    request.setValue("application/json", forHTTPHeaderField: "content-type")
    request.setValue("Bearer \(poolToken)", forHTTPHeaderField: "authorization")
    request.httpBody = try JSONSerialization.data(withJSONObject: body)
    _ = try await session.data(for: request)
  }

  func tellPoolItIsALimit(seconds: Double) async {
    await directLock.lock(for: seconds)
    // The local lock still applies if this fails; the pool learns on the fallback request.
    try? await poolPut("/pool/limit", ["forMs": Int(seconds * 1000)])
  }

  func reportDirectUsage(model: String?, usd: Double) {
    guard usd > 0, pool != nil else { return }
    var fields: [String: Any] = ["usd": usd]
    if let model { fields["model"] = model }
    let body = fields
    Task {
      do { try await poolPut("/pool/report", body) }
      catch { log("could not report usage metadata: \(error.localizedDescription)") }
    }
  }
}

func modelName(_ body: Data) -> String? {
  guard !body.isEmpty, let object = try? JSONSerialization.jsonObject(with: body) as? [String: Any] else { return nil }
  return object["model"] as? String
}

// A usage limit (5-hour, weekly, …) as opposed to a short rate limit. Anthropic marks it
// with the unified rate-limit status header, which is what Claude Code itself reads;
// the message wording is only a fallback, since it varies between limit kinds.
func isUsageLimit(_ response: HTTPURLResponse, _ text: String) -> Bool {
  if response.value(forHTTPHeaderField: "anthropic-ratelimit-unified-status")?.lowercased() == "rejected" { return true }
  return text.range(of: "usage limit|limit reached|reached your .{0,20}limit|weekly limit|5-hour limit",
                    options: [.regularExpression, .caseInsensitive]) != nil
}

// For the log: which limit, and Anthropic's short message (never prompt content).
func describeLimit(_ response: HTTPURLResponse, _ text: String) -> String {
  let status = response.value(forHTTPHeaderField: "anthropic-ratelimit-unified-status") ?? "-"
  let claim = response.value(forHTTPHeaderField: "anthropic-ratelimit-unified-representative-claim") ?? "-"
  let message = ((try? JSONSerialization.jsonObject(with: Data(text.utf8))) as? [String: Any])
    .flatMap { ($0["error"] as? [String: Any])?["message"] as? String } ?? String(text.prefix(120))
  return "unified-status=\(status) claim=\(claim) message=\"\(message.prefix(160))\""
}

func retryAfterSeconds(_ response: HTTPURLResponse) -> Double? {
  // When the limit lifts, from the unified reset header (epoch seconds) if present.
  if let reset = response.value(forHTTPHeaderField: "anthropic-ratelimit-unified-reset").flatMap(Double.init) {
    let seconds = reset - Date().timeIntervalSince1970
    if seconds > 0 { return min(seconds, maxLimitSeconds) }
  }
  guard let value = response.value(forHTTPHeaderField: "retry-after") else { return nil }
  var seconds = Double(value) ?? 0
  if seconds == 0 {
    let formatter = DateFormatter()
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss zzz"
    seconds = formatter.date(from: value).map { $0.timeIntervalSinceNow } ?? 0
  }
  return seconds > 0 ? min(seconds, maxLimitSeconds) : nil
}

// ---------- local metering: prompts stay here, only USD reaches the pool ----------

// USD per million tokens, most specific prefix first (mirrors src/pricing.ts).
let prices: [(prefix: String, input: Double, output: Double, cacheRead: Double)] = [
  ("claude-fable-5-1", 10, 50, 0.25),
  ("claude-mythos-5-1", 10, 50, 0.25),
  ("claude-fable-5", 10, 50, 1),
  ("claude-opus-5-5", 4, 20, 0.2),
  ("claude-opus-5", 5, 25, 0.5),
  ("claude-opus-4", 5, 25, 0.5),
  ("claude-sonnet-5-5", 2, 10, 0.2),
  ("claude-sonnet-5", 2, 10, 0.2),
  ("claude-sonnet-4", 3, 15, 0.3),
  ("claude-haiku-5-5", 0.1, 0.5, 0.01),
  ("claude-haiku-4", 1, 5, 0.1),
]

func costUsd(model: String?, usage: [String: Any]) -> Double {
  let price = prices.first { model?.hasPrefix($0.prefix) == true } ?? prices[0]
  func number(_ value: Any?) -> Double { (value as? NSNumber)?.doubleValue ?? 0 }
  let creation = usage["cache_creation"] as? [String: Any]
  let write5m = creation?["ephemeral_5m_input_tokens"].map(number) ?? number(usage["cache_creation_input_tokens"])
  let write1h = number(creation?["ephemeral_1h_input_tokens"])
  let perMillion =
    number(usage["input_tokens"]) * price.input +
    number(usage["output_tokens"]) * price.output +
    number(usage["cache_read_input_tokens"]) * price.cacheRead +
    write5m * price.input * 1.25 +
    write1h * price.input * 2
  return perMillion / 1_000_000 * ((usage["speed"] as? String) == "fast" ? 2 : 1)
}

// Watches response bytes as they stream through and pulls out token usage: streaming
// responses report it in message_start / message_delta, plain JSON in `usage`.
final class UsageTap {
  private var usage: [String: Any] = [:]
  private var buffer = Data()
  private let isSSE: Bool

  init(contentType: String?) {
    isSSE = contentType?.contains("text/event-stream") ?? false
  }

  func push(_ data: Data) {
    buffer.append(data)
    guard isSSE else { return }
    while let newline = buffer.firstIndex(of: 0x0A) {
      let line = String(decoding: buffer[buffer.startIndex..<newline], as: UTF8.self)
      buffer = buffer.subdata(in: buffer.index(after: newline)..<buffer.endIndex)
      guard line.hasPrefix("data:"),
            let event = try? JSONSerialization.jsonObject(with: Data(line.dropFirst(5).utf8)) as? [String: Any] else { continue }
      if event["type"] as? String == "message_start" { merge((event["message"] as? [String: Any])?["usage"]) }
      if event["type"] as? String == "message_delta" { merge(event["usage"]) }
    }
  }

  func finish() -> [String: Any] {
    if !isSSE, let object = try? JSONSerialization.jsonObject(with: buffer) as? [String: Any] {
      merge(object["usage"])
    }
    return usage
  }

  private func merge(_ partial: Any?) {
    guard let partial = partial as? [String: Any] else { return }
    for (key, value) in partial where !(value is NSNull) { usage[key] = value }
  }
}

@main
struct LembasAgent {
  static func main() async {
    setvbuf(stderr, nil, _IOLBF, 0)
    // A write to a pipe whose reader has gone (a finished MPC helper) must fail, not kill us.
    signal(SIGPIPE, SIG_IGN)
    // No config (left the pool, or never joined): still serve, direct only, and retire.
    let config = FileManager.default.contents(atPath: configPath)
      .flatMap { try? JSONDecoder().decode(AgentConfig.self, from: $0) }
      .flatMap { $0.url.isEmpty || $0.token.isEmpty ? nil : $0 }
    let port = config?.agentPort ?? defaultPort
    let lifecycle = Lifecycle(port: port)
    let agent = Agent(config: config, lifecycle: lifecycle)
    do {
      let server = try await HTTPServer(port: UInt16(port)) { req, out in await agent.handle(req, out) }
      log("listening on http://127.0.0.1:\(port); \(config == nil ? "no pool: direct only" : "direct first, pool only on usage limits")")
      _ = server
      while true {
        await lifecycle.check()
        try? await Task.sleep(nanoseconds: 30 * 1_000_000_000)
      }
    } catch {
      log("could not listen on 127.0.0.1:\(port): \(error.localizedDescription)")
      exit(1) // launchd restarts us
    }
  }
}
