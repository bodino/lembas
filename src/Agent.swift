// lembas agent — the local half of "direct first, pool only on limits".
//
// Claude Code points at http://127.0.0.1:<port> with its normal claude.ai login.
// Every request is forwarded straight to api.anthropic.com from this machine. Only
// when Anthropic says that login hit a usage limit does the agent retry through the
// pool. Prompts never go to the pool in the normal path; only metered USD metadata.
//
// Ships inside lembas.app (Contents/MacOS/lembas-agent) and runs under launchd, so it
// keeps working when the menu bar app is closed. Port of the former installer/agent.mjs.

import Foundation

struct AgentConfig: Decodable {
  var url: String
  var token: String
  var agentPort: Int?
}

let env = ProcessInfo.processInfo.environment
let home = FileManager.default.homeDirectoryForCurrentUser
// Falls back to the pre-rename (claudus) config until the menu bar app migrates it.
let configPath = env["LEMBAS_AGENT_CONFIG"]
  ?? [".config/lembas.json", ".config/claudus-bar.json"].map { home.appendingPathComponent($0).path }
    .first { FileManager.default.fileExists(atPath: $0) } ?? home.appendingPathComponent(".config/lembas.json").path
let anthropic = env["LEMBAS_AGENT_UPSTREAM"] ?? "https://api.anthropic.com"

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

final class Agent {
  let pool: String
  let poolToken: String
  let directLock = DirectLock()

  init(config: AgentConfig) {
    pool = config.url.hasSuffix("/") ? String(config.url.dropLast()) : config.url
    poolToken = config.token
  }

  func handle(_ req: HTTPRequest, _ out: HTTPResponder) async {
    guard req.path.hasPrefix("/v1/") || req.path.hasPrefix("/api/") else {
      return await out.sendJSON(status: 404, ["type": "error", "error": ["type": "not_found_error", "message": "Not found."]])
    }
    do {
      let model = modelName(req.body)

      // The native login recently hit a real usage limit: go straight to the pool until
      // the lock expires, then probe direct again. Only inference calls borrow — Claude
      // Code's /api/* account and usage screens always reflect the member's own login.
      if await directLock.active, req.path.hasPrefix("/v1/") {
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
      if text.range(of: "usage limit|limit reached", options: [.regularExpression, .caseInsensitive]) == nil {
        return await sendFixed(out, upstream, body) // transient rate limit: Claude Code retries direct
      }

      let seconds = retryAfterSeconds(upstream) ?? defaultLimitSeconds
      log("native login hit a usage limit; using the pool for \(Int(seconds))s")
      await tellPoolItIsALimit(seconds: seconds)
      if await tryPool(req, out) { return }
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
    guard usd > 0 else { return }
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

func retryAfterSeconds(_ response: HTTPURLResponse) -> Double? {
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
    guard let data = FileManager.default.contents(atPath: configPath),
          let config = try? JSONDecoder().decode(AgentConfig.self, from: data),
          !config.url.isEmpty, !config.token.isEmpty else {
      log("no usable config at \(configPath) — join a pool from the lembas menu bar app first")
      exit(1)
    }
    let port = UInt16(config.agentPort ?? 8788)
    let agent = Agent(config: config)
    do {
      let server = try await HTTPServer(port: port) { req, out in await agent.handle(req, out) }
      log("listening on http://127.0.0.1:\(port); direct first, pool only on usage limits")
      _ = server
      while true { try? await Task.sleep(nanoseconds: 3600 * 1_000_000_000) }
    } catch {
      log("could not listen on 127.0.0.1:\(port): \(error.localizedDescription)")
      exit(1) // launchd restarts us
    }
  }
}
