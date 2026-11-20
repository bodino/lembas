// lembas agent — the local half of "direct first, friends only on limits".
//
// Claude Code points at http://127.0.0.1:<port> with its normal claude.ai login.
// Every request is forwarded straight to api.anthropic.com from this machine. Only
// when Anthropic says that login hit a usage limit does the agent retry through the
// circle: a friend's Mac, reached by the peer this agent runs (Peer.swift). Prompts
// never leave this Mac in the normal path, and nothing is metered anywhere else.
//
// Ships inside lembas.app; the app copies it to ~/Library/Application Support/lembas and
// runs it under launchd, so it keeps working when the menu bar app is closed — and even
// after the app is deleted, until it has safely retired (see Lifecycle).

import Foundation

struct AgentConfig: Decodable {
  /// This Mac's name in the circle.
  var name: String
  /// What the app shows to drive the agent's control endpoints (the config is 0600).
  var secret: String
  var agentPort: Int?
  // Test hook: act as if the native login were at its usage limit, so every inference
  // request is borrowed. For a second profile that demonstrates borrowing.
  var pretendLimited: Bool?
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

private let logClock: ISO8601DateFormatter = {
  let f = ISO8601DateFormatter()
  f.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
  return f
}()

func log(_ message: String) {
  FileHandle.standardError.write(Data("\(logClock.string(from: Date())) [agent] \(message)\n".utf8))
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
  var idle: TimeInterval { Date().timeIntervalSince(lastRequest) }

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
  let peer: PeerProcess?
  let secret: String
  let directLock = DirectLock()
  let lifecycle: Lifecycle
  let port: Int
  // The agent flipped the peer to away on idleness; the next request flips it back.
  let autoAway = AutoAway()

  // Without a config the agent still forwards straight to Anthropic, so Claude Code
  // keeps working while it retires.
  init(config: AgentConfig?, lifecycle: Lifecycle, port: Int) {
    peer = config.map { PeerProcess(name: $0.name) }
    secret = config?.secret ?? ""
    self.lifecycle = lifecycle
    self.port = port
  }

  // Only Claude Code on this Mac may talk to the agent. A browser tab could reach a
  // loopback port too (a plain POST needs no preflight, and DNS rebinding gets around
  // the rest), and when the login is at its limit, spend a friend's quota. Browsers
  // always send Origin on such requests and Claude Code never does; the Host must be
  // this loopback port; model calls are JSON.
  func fromClaudeCode(_ req: HTTPRequest) -> Bool {
    if req.header("origin") != nil || req.header("referer") != nil { return false }
    // Browsers mark every request they make, even a GET with no referrer; Claude Code never does.
    if req.header("sec-fetch-site") != nil || req.header("sec-fetch-mode") != nil { return false }
    let hosts: Set<String> = ["127.0.0.1:\(port)", "localhost:\(port)", "[::1]:\(port)"]
    guard let host = req.header("host"), hosts.contains(host.lowercased()) else { return false }
    if req.method == "POST", !(req.header("content-type") ?? "").lowercased().hasPrefix("application/json") { return false }
    return true
  }

  private func usingPool() async -> Bool {
    let retiring = await lifecycle.retiring
    return peer != nil && !retiring
  }

  func handle(_ req: HTTPRequest, _ out: HTTPResponder) async {
    if req.path.hasPrefix("/lembas/") { return await handleControl(req, out) }
    guard req.path.hasPrefix("/v1/") || req.path.hasPrefix("/api/") else {
      return await out.sendJSON(status: 404, ["type": "error", "error": ["type": "not_found_error", "message": "Not found."]])
    }
    guard fromClaudeCode(req) else {
      log("refused a request that didn't come from Claude Code (\(req.method) \(req.path), host \(req.header("host") ?? "-"))")
      return await out.sendJSON(status: 403, ["type": "error", "error": ["type": "permission_error", "message": "lembas agent only serves Claude Code on this Mac."]])
    }
    await lifecycle.touch()
    do {
      let model = modelName(req.body)
      let usePool = await usingPool()
      if usePool, req.path.hasPrefix("/v1/"), await autoAway.back() { await setAway(false) }

      // The native login recently hit a real usage limit: go straight to the pool until
      // the lock expires, then probe direct again. Only model calls borrow — Claude
      // Code's /api/* account and usage screens always reflect the member's own login,
      // and a lender's Mac refuses its login to anything else.
      let limited = forcePool || currentConfig()?.pretendLimited == true ? true : await directLock.active
      let borrowable = usePool && lendable(req)
      if borrowable, limited {
        if await tryPool(req, out) { return }
      }

      guard let request = upstreamRequest(anthropic, req) else {
        return await out.sendJSON(status: 400, ["type": "error", "error": ["type": "invalid_request_error", "message": "Bad request path."]])
      }
      let (bytes, upstream) = try await open(request, out)

      if upstream.statusCode != 429 {
        let tap = UsageTap(contentType: upstream.value(forHTTPHeaderField: "content-type"))
        await relay(bytes, upstream, out, tap: tap)
        // What it cost, for the peer on this Mac and no further: against what friends
        // borrowed, it says how much of each window was theirs.
        let usd = costUsd(model: model, usage: tap.finish())
        if usd > 0, let peer { Task { _ = try? await peer.command(["cmd": "spent", "usd": usd]) } }
        return
      }

      var body = Data()
      for try await byte in bytes { body.append(byte) }
      let text = String(decoding: body, as: UTF8.self)
      log("429 from Anthropic: \(describeLimit(upstream, text))")
      if !isUsageLimit(upstream, text) {
        return await sendFixed(out, upstream, body) // transient rate limit: Claude Code retries direct
      }

      if borrowable {
        let seconds = retryAfterSeconds(upstream) ?? defaultLimitSeconds
        log("native login hit a usage limit; borrowing from the circle for \(Int(seconds))s")
        await directLock.lock(for: seconds)
        if await tryPool(req, out) { return }
      }
      await sendFixed(out, upstream, body) // pool down/no donors: preserve Anthropic's own error
    } catch {
      log("direct request to Anthropic failed (\(req.method) \(req.path)): \(error.localizedDescription)")
      if !out.closed {
        await out.sendJSON(status: 502, ["type": "error", "error": ["type": "api_error", "message": "lembas agent could not reach Anthropic."]])
      }
    }
  }

  // ---------- forwarding ----------

  func upstreamRequest(_ base: String, _ req: HTTPRequest) -> URLRequest? {
    guard req.path.utf8.allSatisfy(urlPathByte), let url = URL(string: base + req.path) else { return nil }
    var request = URLRequest(url: url)
    request.httpMethod = req.method
    for (name, value) in req.headers where !requestHopHeaders.contains(name) {
      request.addValue(value, forHTTPHeaderField: name)
    }
    request.setValue("identity", forHTTPHeaderField: "accept-encoding")
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

  // Borrowing is private, and only private: the request goes through the pool's
  // helper or not at all. Any failure pauses borrowing, and Claude Code gets
  // Anthropic's own limit error; a pool without the helper can't lend.
  func tryPool(_ req: HTTPRequest, _ out: HTTPResponder) async -> Bool {
    guard peer != nil else { return false }
    switch await tryPrivate(req, out) {
    case .served: return true
    case .failed: return false
    }
  }

  // ---------- the app's control endpoints: the peer, through the agent ----------
  //
  // Only the app, with the secret from the config file, may read the circle or change
  // what this Mac lends. GET /lembas/status, POST /lembas/cmd {"cmd": …} (forwarded to
  // the peer), POST /lembas/leave (stops the peer and forgets the circle).

  func handleControl(_ req: HTTPRequest, _ out: HTTPResponder) async {
    guard !secret.isEmpty, req.header("authorization") == "Bearer \(secret)" else {
      return await out.sendJSON(status: 401, ["error": ["type": "unauthorized", "message": "lembas agent: not the app."]])
    }
    guard let peer else {
      return await out.sendJSON(status: 503, ["error": ["type": "no_peer", "message": "no circle on this Mac"]])
    }
    do {
      switch (req.method, req.path) {
      case ("GET", "/lembas/status"):
        let status = try await peer.currentStatus()
        await out.sendJSON(status: 200, ["status": status, "running": true])
      case ("POST", "/lembas/cmd"):
        guard let cmd = (try? JSONSerialization.jsonObject(with: req.body)) as? [String: Any], cmd["cmd"] is String else {
          return await out.sendJSON(status: 400, ["error": ["type": "bad_request", "message": "a {\"cmd\"} object"]])
        }
        let result = try await peer.command(cmd)
        if cmd["cmd"] as? String == "away" { await autoAway.manual() }
        await out.sendJSON(status: 200, ["result": result])
      case ("POST", "/lembas/leave"):
        await peer.stop()
        try? FileManager.default.removeItem(atPath: peerDir)
        try? FileManager.default.removeItem(atPath: loginPath)
        log("left the circle: the peer is stopped and its key, circle and login are deleted")
        await out.sendJSON(status: 200, ["ok": true])
      default:
        await out.sendJSON(status: 404, ["error": ["type": "not_found", "message": "Not found."]])
      }
    } catch {
      await out.sendJSON(status: 502, ["error": ["type": "peer", "message": "\(error)"]])
    }
  }

  func setAway(_ away: Bool) async {
    guard let peer else { return }
    _ = try? await peer.command(["cmd": "away", "away": away])
  }

  // Away by itself after a while without Claude Code (the number is the owner's), back
  // on the next request; a switch the owner flipped stays as flipped.
  func watchIdleness() async {
    while true {
      try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
      await awayIfIdle()
    }
  }

  // One check, in a function of its own: with the body inline in the loop above,
  // Swift 6.3's optimizer (the one the release is built with) never finishes.
  private func awayIfIdle() async {
    guard let peer, await peer.running, let status = try? await peer.currentStatus(maxAge: 60) else { return }
    let away = status["away"] as? Bool ?? false
    let minutes = ((status["policy"] as? [String: Any])?["away_after_minutes"] as? NSNumber)?.doubleValue ?? 30
    if !away, await lifecycle.idle > minutes * 60, await autoAway.goAway() {
      log("no Claude Code request for \(Int(minutes)) min: away")
      await setAway(true)
    }
  }
}

// Whether the agent, not the owner, set the away switch.
actor AutoAway {
  private var byAgent = false
  func goAway() -> Bool { byAgent = true; return true }
  // Called on a request: true if the agent should flip the switch back.
  func back() -> Bool { defer { byAgent = false }; return byAgent }
  func manual() { byAgent = false }
}

// What a lender lends its login to (model_request in the helper's peer.rs): a model
// call, or the count of its tokens.
func lendable(_ req: HTTPRequest) -> Bool {
  let path = req.path.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? req.path
  return req.method == "POST" && (path == "/v1/messages" || path == "/v1/messages/count_tokens")
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

// ---------- local metering: prompts stay here, only USD reaches the peer ----------

// USD per million tokens, most specific prefix first.
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
      .flatMap { $0.name.isEmpty || $0.secret.isEmpty ? nil : $0 }
    let port = config?.agentPort ?? defaultPort
    let lifecycle = Lifecycle(port: port)
    let agent = Agent(config: config, lifecycle: lifecycle, port: port)
    do {
      let server = try await HTTPServer(port: UInt16(port)) { req, out in await agent.handle(req, out) }
      log("listening on http://127.0.0.1:\(port); \(config == nil ? "no circle: direct only" : "direct first, friends only on usage limits")")
      _ = server
      if let peer = agent.peer {
        _ = await LoginFile.refreshIfNeeded()
        await peer.start()
        Task { await agent.watchIdleness() }
        Task {
          while true {
            try? await Task.sleep(nanoseconds: 60 * 1_000_000_000)
            _ = await LoginFile.refreshIfNeeded()
          }
        }
      }
      while true {
        await lifecycle.check()
        if await lifecycle.retiring, let peer = agent.peer { await peer.stop() }
        try? await Task.sleep(nanoseconds: 30 * 1_000_000_000)
      }
    } catch {
      log("could not listen on 127.0.0.1:\(port): \(error.localizedDescription)")
      exit(1) // launchd restarts us
    }
  }
}
