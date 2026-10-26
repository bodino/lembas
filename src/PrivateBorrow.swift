// Borrowing: the agent's side of borrowed requests with spliced token records.
//
// A borrowed request never goes to the pool as HTTP. The agent keeps one session with the pool for as long as it has requests: a
// WebSocket to the pool's /pool/borrow, bridged to a `lembas-mpc proxy` helper that
// runs the TLS connections to Anthropic itself and holds their keys alone. Each
// request from Claude Code goes to the helper's local port as plain HTTP; the helper
// sends everything but the token, and the pool's helper writes the one record that
// carries a lender's token, computed so that it never sees the keys and this side
// never sees the token (see docs/mpc-tls.md). The pool cannot read the request or the
// answer, so the agent tells it what happened after each request: usage to meter, or
// a usage limit so it parks that lender. Five Claude Code sessions share the one
// helper; it opens a connection per request in flight and reuses them.

import Foundation

// Built by ./build.sh and installed next to the agent by the app; the launchd job can
// point elsewhere (tests).
let mpcHelperPath = env["LEMBAS_MPC_HELPER"]
  ?? URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().appendingPathComponent("lembas-mpc").path
// Test hook: borrow every /v1/ request, as if the native login had just hit its limit.
let forcePool = env["LEMBAS_AGENT_FORCE_POOL"] == "1"

let anthropicHost = "api.anthropic.com"
// Headers the agent never forwards; the helper drops the same and supplies its own.
let templateDropHeaders: Set<String> = ["host", "connection", "content-length", "authorization", "x-api-key",
                                        "accept-encoding", "transfer-encoding", "expect"]
// The pool's record is the request line, Host, Content-Length and the Authorization
// line, at most lembas-mpc's MAX_HEADER_LEN (320 bytes) with the token span aligned.
// What is left for the request line, with room to spare.
let maxRequestLine = 110
// How long to wait for the helper to come up (it pays the OT setup first).
let sessionStartTimeout: TimeInterval = 90

// Re-read per borrow, so config changes take effect without restarting the agent.
func currentConfig() -> AgentConfig? {
  FileManager.default.contents(atPath: configPath).flatMap { try? JSONDecoder().decode(AgentConfig.self, from: $0) }
}

enum PrivateBorrowError: Error, CustomStringConvertible {
  case pool(String), helper(String), template(String)
  /// The pool has no helper: a statement about the pool, not a failure.
  case unsupported
  var description: String {
    switch self {
    case .pool(let m): return "pool: \(m)"
    case .helper(let m): return "helper: \(m)"
    case .template(let m): return "request: \(m)"
    case .unsupported: return "pool: it cannot lend privately (no helper)"
    }
  }
}

/// How a private attempt ended, for the agent to decide what comes next.
enum PrivateAttempt {
  case served // the response reached Claude Code, whatever its status
  case unsupported // the pool cannot lend privately at all
  case failed // the private path failed; borrowing pauses
}

enum PrivateOutcome {
  case served // the response reached Claude Code, whatever its status
  case lenderExhausted // that lender's token hit a limit or is dead; the pool parks it on our report
}

extension Agent {
  // Up to three lenders: each attempt gets whichever the pool picks next.
  func tryPrivate(_ req: HTTPRequest, _ out: HTTPResponder) async -> PrivateAttempt {
    guard let pool else { return .failed }
    for attempt in 0..<3 {
      let session: PrivateSession
      do {
        session = try await PrivateSessions.shared.session(pool: pool, poolToken: poolToken)
      } catch {
        if case PrivateBorrowError.unsupported = error {
          log("private borrow: the pool has no helper")
          return .unsupported
        }
        log("private borrow: no session: \(error)")
        return .failed
      }
      do {
        switch try await session.perform(req, out, agent: self) {
        case .served: return .served
        case .lenderExhausted:
          // Our report parks that lender; give it a moment to land before asking again.
          if attempt < 2 { try? await Task.sleep(nanoseconds: 300_000_000) }
        }
      } catch {
        log("private borrow failed: \(error)")
        if !session.alive { await PrivateSessions.shared.discard(session) }
        return .failed
      }
    }
    return .failed
  }
}

// The one session per agent, started on first use and replaced when it dies.
actor PrivateSessions {
  static let shared = PrivateSessions()
  private var current: PrivateSession?
  private var starting: Task<PrivateSession, Error>?

  func session(pool: String, poolToken: String) async throws -> PrivateSession {
    if let current {
      if current.alive { return current }
      current.shutdown() // dead, but its helper or socket may still be around
      self.current = nil
    }
    if let starting { return try await starting.value }
    let task = Task { try await PrivateSession.start(pool: pool, poolToken: poolToken) }
    starting = task
    defer { starting = nil }
    let session = try await task.value
    current = session
    return session
  }

  func discard(_ session: PrivateSession) {
    if current === session {
      current = nil
      session.shutdown()
    }
  }
}

final class PrivateSession {
  let socketPath: String
  private let ws: URLSessionWebSocketTask
  private let helper: Process
  private let dir: URL
  private let inbound: Task<Void, Error>
  private let outbound: Task<Void, Error>
  private let liveness: Liveness

  var alive: Bool { liveness.alive && helper.isRunning }

  private init(socketPath: String, ws: URLSessionWebSocketTask, helper: Process, dir: URL,
               inbound: Task<Void, Error>, outbound: Task<Void, Error>, liveness: Liveness) {
    self.socketPath = socketPath
    self.ws = ws
    self.helper = helper
    self.dir = dir
    self.inbound = inbound
    self.outbound = outbound
    self.liveness = liveness
  }

  final class Liveness: @unchecked Sendable {
    private let lock = NSLock()
    private var value = true
    var alive: Bool { lock.withLock { value } }
    func end() { lock.withLock { value = false } }
  }

  static func start(pool: String, poolToken: String) async throws -> PrivateSession {
    sweepStaleSessionDirectories()
    // 1. The WebSocket; the pool says whether it can lend privately at all.
    guard var parts = URLComponents(string: pool + "/pool/borrow") else { throw PrivateBorrowError.pool("bad pool URL") }
    parts.scheme = parts.scheme == "https" ? "wss" : "ws"
    var wsRequest = URLRequest(url: parts.url!)
    wsRequest.setValue("Bearer \(poolToken)", forHTTPHeaderField: "authorization")
    let ws = session.webSocketTask(with: wsRequest)
    ws.maximumMessageSize = 64 << 20
    ws.resume()
    let first: String
    do {
      // The deadline closes the WebSocket itself: receive() doesn't notice cancellation,
      // and a pool that accepts and says nothing must not hold the agent forever.
      let message = try await withTimeout(sessionStartTimeout, "the pool's session greeting",
                                          onTimeout: { ws.cancel(with: .goingAway, reason: nil) }, { try await ws.receive() })
      guard case .string(let text) = message else { throw PrivateBorrowError.pool("expected a session greeting first") }
      first = text
    } catch {
      ws.cancel(with: .goingAway, reason: nil)
      throw error
    }
    guard let hello = try? JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any] else {
      ws.cancel(with: .protocolError, reason: nil)
      throw PrivateBorrowError.pool("expected a session greeting first")
    }
    guard hello["type"] as? String == "session" else {
      ws.cancel(with: .normalClosure, reason: nil)
      if hello["code"] as? String == "unsupported" { throw PrivateBorrowError.unsupported }
      throw PrivateBorrowError.pool("\(hello["code"] ?? "error"): \(hello["message"] ?? first)")
    }

    // 2. The helper. Its stdin/stdout are the link to the pool; it serves requests on
    //    a Unix socket in a directory only this user can enter (a loopback TCP port
    //    would be open to every process of every user on the Mac, and the session
    //    spends a lender's quota); its logs join ours.
    let fm = FileManager.default
    // Short names: a Unix socket path must fit in 104 bytes, and the per-user temporary
    // directory already takes about half of that.
    let dir = fm.temporaryDirectory.appendingPathComponent("lembas-\(UUID().uuidString.prefix(8))")
    try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let socketPath = dir.appendingPathComponent("s").path
    guard socketPath.utf8.count < 100 else { throw PrivateBorrowError.helper("temporary directory path too long for a socket: \(socketPath)") }
    let helper = Process()
    helper.executableURL = URL(fileURLWithPath: mpcHelperPath)
    helper.arguments = ["proxy", "--stdio", "--socket", socketPath, "--server-name", anthropicHost]
    helper.environment = ["RUST_LOG": env["LEMBAS_MPC_LOG"] ?? "warn"]
    let toHelper = Pipe(), fromHelper = Pipe()
    helper.standardInput = toHelper
    helper.standardOutput = fromHelper
    helper.standardError = FileHandle.standardError
    let liveness = Liveness()
    helper.terminationHandler = { _ in liveness.end(); ws.cancel(with: .goingAway, reason: nil) }
    do { try helper.run() } catch {
      ws.cancel(with: .goingAway, reason: nil)
      try? fm.removeItem(at: dir)
      throw PrivateBorrowError.helper("could not start \(mpcHelperPath): \(error.localizedDescription)")
    }

    // 3. The bridge: pool → helper and helper → pool, for the life of the session.
    let inbound = Task {
      let stdin = toHelper.fileHandleForWriting
      defer { try? stdin.close(); liveness.end() }
      while true {
        switch try await ws.receive() {
        case .data(let data):
          if helper.isRunning { try stdin.write(contentsOf: data) }
        case .string(let text):
          // The pool only speaks up when something failed on its side.
          log("private borrow: pool says \(text)")
          throw PrivateBorrowError.pool(text)
        @unknown default: break
        }
      }
    }
    let outbound = Task {
      do {
        for await chunk in chunks(of: fromHelper.fileHandleForReading) { try await ws.send(.data(chunk)) }
      } catch {
        // The pool can't hear us any more: the session is over, not merely quiet.
        log("private borrow: link to the pool failed: \(error.localizedDescription)")
        liveness.end()
        ws.cancel(with: .goingAway, reason: nil)
        throw error
      }
    }

    // 4. The socket, once the helper has set up with the pool.
    let deadline = Date().addingTimeInterval(sessionStartTimeout)
    var ready = false
    while !ready {
      if fm.fileExists(atPath: socketPath) {
        ready = true
        break
      }
      guard helper.isRunning, liveness.alive, Date() < deadline else { break }
      try await Task.sleep(nanoseconds: 50_000_000)
    }
    guard ready else {
      inbound.cancel()
      outbound.cancel()
      if helper.isRunning { helper.terminate() }
      ws.cancel(with: .goingAway, reason: nil)
      try? fm.removeItem(at: dir)
      throw PrivateBorrowError.helper("session did not come up")
    }
    log("private borrow: session ready on \(socketPath)")
    return PrivateSession(socketPath: socketPath, ws: ws, helper: helper, dir: dir, inbound: inbound, outbound: outbound, liveness: liveness)
  }

  // One request through the helper's local port.
  func perform(_ request: HTTPRequest, _ out: HTTPResponder, agent: Agent) async throws -> PrivateOutcome {
    let model = modelName(request.body)
    var bytes = Data(try PrivateSession.requestHead(for: request).utf8)
    bytes.append(request.body)

    let fd = try connectLocal(socketPath)
    // Owns the descriptor; the reader task below keeps it until EOF or we return.
    let handle = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
    let writer = Task.detached {
      try writeAll(fd, bytes)
    }
    var response = HTTPResponseReader(chunks(of: handle))
    let head: HTTPURLResponse
    do {
      // The helper answers within its own limits (90 s to splice, 10 min idle on a
      // response); past that the session is wedged, and the request must not hang.
      // The path was checked when the request head was built, so this URL exists.
      let url = URL(string: "https://\(anthropicHost)\(request.path)") ?? URL(string: "https://\(anthropicHost)/")!
      head = try await withTimeout(responseHeadTimeout, "the response head", onTimeout: { _ = Darwin.shutdown(fd, SHUT_RDWR) }, {
        try await response.head(url: url)
      })
    } catch {
      writer.cancel()
      if !alive { throw PrivateBorrowError.helper("session ended: \(error)") }
      throw error
    }
    _ = try await writer.value

    // The helper's own answers: nobody lending (503) or a failure (502).
    if let kind = head.value(forHTTPHeaderField: "x-lembas-error") {
      var body = Data()
      for try await chunk in response.body { body.append(chunk) }
      let message = (try? JSONSerialization.jsonObject(with: body) as? [String: Any])
        .flatMap { ($0["error"] as? [String: Any])?["message"] as? String } ?? String(decoding: body, as: UTF8.self)
      throw kind == "refused" ? PrivateBorrowError.pool("refused: \(message)") : PrivateBorrowError.helper(message)
    }
    let reqNo = head.value(forHTTPHeaderField: "x-lembas-request").flatMap(Int.init) ?? 0
    log("private borrow: request \(reqNo) \(request.method) \(request.path) (\(request.body.count) bytes) → \(head.statusCode)")

    let outcome: PrivateOutcome
    let tap = UsageTap(contentType: head.value(forHTTPHeaderField: "content-type"))
    if head.statusCode == 429 || head.statusCode == 401 {
      // Decide before answering Claude Code: a limit on this lender means another lender.
      var body = Data()
      for try await chunk in response.body { body.append(chunk) }
      let text = String(decoding: body, as: UTF8.self)
      if head.statusCode == 401 {
        log("private borrow: the lender's token is dead (401)")
        report(["type": "dead", "req": reqNo, "status": 401, "model": model as Any])
        outcome = .lenderExhausted
      } else if isUsageLimit(head, text) {
        let seconds = retryAfterSeconds(head) ?? defaultLimitSeconds
        log("private borrow: the lender's token hit its limit: \(describeLimit(head, text))")
        report(["type": "limit", "req": reqNo, "status": 429, "forMs": Int(seconds * 1000), "model": model as Any])
        outcome = .lenderExhausted
      } else {
        await agent.sendFixed(out, head, body) // transient rate limit: Claude Code retries
        report(["type": "result", "req": reqNo, "status": 429, "usd": 0, "model": model as Any])
        outcome = .served
      }
    } else {
      var headers = agent.responseHeaders(head)
      headers = headers.filter { $0.0.lowercased() != "x-lembas-request" }
      await out.start(status: head.statusCode, headers: headers)
      var pending = Data()
      do {
        for try await chunk in response.body {
          pending.append(chunk)
          if pending.last == 0x0A || pending.count >= 16 << 10 {
            tap.push(pending)
            let delivered = await out.chunk(pending)
            pending.removeAll(keepingCapacity: true) // metered once, whether or not it was delivered
            guard delivered else { break }
          }
        }
      } catch {
        if !out.closed { log("private borrow: response ended early: \(error)") }
      }
      tap.push(pending)
      await out.chunk(pending)
      await out.end()
      let usd = costUsd(model: model, usage: tap.finish())
      report(["type": "result", "req": reqNo, "status": head.statusCode, "usd": usd, "model": model as Any])
      outcome = .served
    }
    return outcome
  }

  // The request as the helper wants it: plain HTTP/1.1 with Content-Length. Same
  // header policy as the pool's relay: Claude Code's headers minus the per-hop ones,
  // the two beta flags a subscription token needs, a Claude Code user agent, no
  // compression. The helper puts the request line, Host, Content-Length and the
  // Authorization line in the pool's record and sends the rest itself.
  static func requestHead(for request: HTTPRequest) throws -> String {
    // Both come from Claude Code's request line, but they go into the pool's record as
    // text: a method that is a token and a path of visible ASCII, or nothing.
    guard !request.method.isEmpty, request.method.utf8.allSatisfy({ $0 >= 0x41 && $0 <= 0x5a }),
          request.path.hasPrefix("/"), request.path.utf8.allSatisfy(urlPathByte),
          let url = URL(string: "https://\(anthropicHost)\(request.path)") else {
      throw PrivateBorrowError.template("bad request line")
    }
    _ = url
    let line = "\(request.method) \(request.path) HTTP/1.1\r\n"
    guard line.utf8.count <= maxRequestLine else {
      throw PrivateBorrowError.template("request line too long for private borrowing (\(line.utf8.count) bytes)")
    }
    var text = line + "Host: \(anthropicHost)\r\nContent-Length: \(request.body.count)\r\n"
    var betas = ["claude-code-20250219", "oauth-2025-04-20"]
    var userAgent = "claude-cli/2.1.0 (external, cli)"
    for (name, value) in request.headers where !templateDropHeaders.contains(name) {
      guard !value.contains("\r"), !value.contains("\n"), !name.contains(":") else { throw PrivateBorrowError.template("bad header \(name)") }
      switch name {
      case "anthropic-beta":
        for beta in value.split(separator: ",").map({ $0.trimmingCharacters(in: .whitespaces) }) where !beta.isEmpty && !betas.contains(beta) {
          betas.append(beta)
        }
      case "user-agent":
        if value.hasPrefix("claude-cli/") { userAgent = value }
      default:
        text += "\(name): \(value)\r\n"
      }
    }
    text += "anthropic-beta: \(betas.joined(separator: ","))\r\nuser-agent: \(userAgent)\r\n\r\n"
    return text
  }

  private func report(_ object: [String: Any]) {
    let clean = object.filter { !($0.value is NSNull) }
    guard let data = try? JSONSerialization.data(withJSONObject: clean) else { return }
    ws.send(.string(String(decoding: data, as: UTF8.self))) { _ in }
  }

  func shutdown() {
    inbound.cancel()
    outbound.cancel()
    if helper.isRunning { helper.terminate() }
    ws.cancel(with: .goingAway, reason: nil)
    try? FileManager.default.removeItem(at: dir)
  }
}

// A TCP connection to the helper's local port.
// How long a borrowed request may take to produce its response head: the helper's own
// splice and response limits, with a margin.
let responseHeadTimeout: TimeInterval = 700

struct TimedOut: Error, CustomStringConvertible {
  let what: String
  var description: String { "timed out waiting for \(what)" }
}

// The first of the two tasks (or the caller's cancellation) to finish decides; the
// others are cancelled and their results dropped.
final class TimeoutRace<T: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<T, Error>?
  private var result: Result<T, Error>?
  private var tasks: [Task<Void, Never>] = []
  func start(_ continuation: CheckedContinuation<T, Error>) {
    let settled = lock.withLock { () -> Result<T, Error>? in
      if result == nil { self.continuation = continuation }
      return result
    }
    if let settled { continuation.resume(with: settled) }
  }
  func add(_ task: Task<Void, Never>) {
    let over = lock.withLock { () -> Bool in tasks.append(task); return result != nil }
    if over { task.cancel() }
  }
  func finish(_ outcome: Result<T, Error>) -> Bool {
    let (first, continuation, tasks) = lock.withLock { () -> (Bool, CheckedContinuation<T, Error>?, [Task<Void, Never>]) in
      guard result == nil else { return (false, nil, []) }
      result = outcome
      defer { self.continuation = nil }
      return (true, self.continuation, self.tasks)
    }
    guard first else { return false }
    tasks.forEach { $0.cancel() }
    continuation?.resume(with: outcome)
    return true
  }
}

// Resolves the caller at the deadline whether or not `op` has noticed: a task group
// would wait for the operation to leave, and an await on a socket read or a URLSession
// callback may never do so. `onTimeout` is where to pull the plug (close the socket,
// cancel the WebSocket) so the orphaned operation ends too, instead of hanging on
// behind the caller's back.
func withTimeout<T: Sendable>(_ seconds: TimeInterval, _ what: String, onTimeout: @escaping @Sendable () -> Void = {},
                              _ op: @escaping @Sendable () async throws -> T) async throws -> T {
  let race = TimeoutRace<T>()
  return try await withTaskCancellationHandler {
    try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<T, Error>) in
      race.start(continuation)
      race.add(Task {
        let outcome: Result<T, Error>
        do { outcome = .success(try await op()) } catch { outcome = .failure(error) }
        _ = race.finish(outcome)
      })
      race.add(Task {
        try? await Task.sleep(nanoseconds: UInt64(seconds * 1_000_000_000))
        guard !Task.isCancelled, race.finish(.failure(TimedOut(what: what))) else { return }
        onTimeout()
      })
    }
  } onCancel: {
    _ = race.finish(.failure(CancellationError()))
  }
}

// Session directories an agent that was killed (a restart, a crash) left behind: the
// socket of a dead session refuses to connect; one that connects belongs to a live
// session, possibly another profile's agent, and is left alone. So is anything recent:
// another agent may have made its directory and not bound its socket yet.
func sweepStaleSessionDirectories() {
  let fm = FileManager.default
  guard let names = try? fm.contentsOfDirectory(atPath: fm.temporaryDirectory.path) else { return }
  for name in names where name.hasPrefix("lembas-") {
    let dir = fm.temporaryDirectory.appendingPathComponent(name)
    guard let modified = (try? fm.attributesOfItem(atPath: dir.path))?[.modificationDate] as? Date,
          Date().timeIntervalSince(modified) > 600 else { continue }
    if let fd = try? connectLocal(dir.appendingPathComponent("s").path) {
      close(fd)
      continue
    }
    try? fm.removeItem(at: dir)
  }
}

// A byte a URL path or query may carry (RFC 3986 unreserved, reserved and %): what
// Claude Code sends, and nothing a URL parser or the pool's record would read otherwise.
func urlPathByte(_ b: UInt8) -> Bool {
  if (0x30...0x39).contains(b) || (0x41...0x5a).contains(b) || (0x61...0x7a).contains(b) { return true }
  return "-._~:/?#[]@!$&'()*+,;=%".utf8.contains(b)
}

// The helper's Unix socket in the session directory (0700, this user only).
func connectLocal(_ path: String) throws -> Int32 {
  let fd = socket(AF_UNIX, SOCK_STREAM, 0)
  guard fd >= 0 else { throw PrivateBorrowError.helper("socket: \(String(cString: strerror(errno)))") }
  var addr = sockaddr_un()
  addr.sun_family = sa_family_t(AF_UNIX)
  let bytes = Array(path.utf8)
  guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else {
    close(fd)
    throw PrivateBorrowError.helper("session socket path too long")
  }
  withUnsafeMutableBytes(of: &addr.sun_path) { raw in
    raw.copyBytes(from: bytes)
    raw[bytes.count] = 0
  }
  addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
  let rc = withUnsafePointer(to: &addr) {
    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
  }
  guard rc == 0 else {
    let message = String(cString: strerror(errno))
    close(fd)
    throw PrivateBorrowError.helper("connecting to the session: \(message)")
  }
  return fd
}

func writeAll(_ fd: Int32, _ data: Data) throws {
  var offset = 0
  while offset < data.count {
    let n = data.withUnsafeBytes { raw in write(fd, raw.baseAddress! + offset, data.count - offset) }
    if n > 0 { offset += n } else if n < 0 && errno == EINTR { continue } else {
      throw PrivateBorrowError.helper("writing the request: \(String(cString: strerror(errno)))")
    }
  }
}

// Reads a FileHandle as it fills, in whatever pieces arrive; ends at EOF. Plain
// blocking read(2) on its own thread: it returns what is there (FileHandle's
// readData(ofLength:) would wait for the full length), and EOF is unambiguous.
func chunks(of handle: FileHandle) -> AsyncStream<Data> {
  AsyncStream { continuation in
    let reader = Task.detached { [handle] in // keeps the descriptor open until EOF
      var buffer = [UInt8](repeating: 0, count: 64 << 10)
      while !Task.isCancelled {
        let n = buffer.withUnsafeMutableBytes { read(handle.fileDescriptor, $0.baseAddress, $0.count) }
        if n > 0 { continuation.yield(Data(buffer[0..<n])) } else if n == 0 || errno != EINTR { break }
      }
      continuation.finish()
    }
    continuation.onTermination = { _ in reader.cancel() }
  }
}

// An HTTP/1.1 response arriving in pieces: the head, then the body with chunked
// transfer coding removed (Anthropic streams that way), until EOF.
struct HTTPResponseReader {
  private var iterator: AsyncStream<Data>.AsyncIterator
  private var buffer = Data()
  private var chunked = false

  init(_ stream: AsyncStream<Data>) { iterator = stream.makeAsyncIterator() }

  mutating func head(url: URL) async throws -> HTTPURLResponse {
    while true {
      if let end = buffer.range(of: Data("\r\n\r\n".utf8)) {
        let text = String(decoding: buffer[buffer.startIndex..<end.lowerBound], as: UTF8.self)
        buffer = buffer.subdata(in: end.upperBound..<buffer.endIndex)
        var lines = text.components(separatedBy: "\r\n")
        let status = lines.removeFirst().split(separator: " ")
        guard status.count >= 2, let code = Int(status[1]) else { throw PrivateBorrowError.helper("malformed status line") }
        var headers: [String: String] = [:]
        for line in lines {
          guard let colon = line.firstIndex(of: ":") else { continue }
          let name = line[..<colon].lowercased()
          let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
          headers[name] = headers[name].map { $0 + ", " + value } ?? value
        }
        chunked = headers["transfer-encoding"]?.lowercased().contains("chunked") ?? false
        guard let response = HTTPURLResponse(url: url, statusCode: code, httpVersion: "HTTP/1.1", headerFields: headers) else {
          throw PrivateBorrowError.helper("malformed response head")
        }
        return response
      }
      guard let more = await iterator.next() else { throw PrivateBorrowError.helper("no response") }
      buffer.append(more)
      if buffer.count > 64 << 10 { throw PrivateBorrowError.helper("response head too large") }
    }
  }

  // Body pieces as they arrive, decoded.
  var body: AsyncThrowingStream<Data, Error> {
    mutating get {
      var iterator = self.iterator
      var decoder = ChunkedDecoder()
      let chunked = self.chunked
      let initial = buffer
      buffer = Data()
      return AsyncThrowingStream { continuation in
        let pump = Task {
          var first = true
          do {
            while true {
              let piece: Data
              if first, !initial.isEmpty { piece = initial } else {
                guard let next = await iterator.next() else { break }
                piece = next
              }
              first = false
              if chunked {
                let decoded = try decoder.feed(piece)
                if !decoded.isEmpty { continuation.yield(decoded) }
                if decoder.done { break }
              } else {
                continuation.yield(piece)
              }
            }
            continuation.finish()
          } catch {
            continuation.finish(throwing: error)
          }
        }
        continuation.onTermination = { _ in pump.cancel() }
      }
    }
  }
}

struct ChunkedDecoder {
  private enum State { case size, data(Int), crlf, trailer }
  private var state = State.size
  private var pending = Data()
  private(set) var done = false

  mutating func feed(_ input: Data) throws -> Data {
    pending.append(input)
    var out = Data()
    while true {
      switch state {
      case .size:
        guard let eol = pending.range(of: Data("\r\n".utf8)) else { return out }
        let line = String(decoding: pending[pending.startIndex..<eol.lowerBound], as: UTF8.self)
        pending = pending.subdata(in: eol.upperBound..<pending.endIndex)
        guard let size = Int(line.split(separator: ";").first.map(String.init) ?? "", radix: 16), size >= 0 else {
          throw PrivateBorrowError.helper("bad chunk size")
        }
        state = size == 0 ? .trailer : .data(size)
      case .data(let remaining):
        let take = min(remaining, pending.count)
        out.append(pending.prefix(take))
        pending = pending.subdata(in: (pending.startIndex + take)..<pending.endIndex)
        if take == remaining { state = .crlf } else { state = .data(remaining - take); return out }
      case .crlf:
        guard pending.count >= 2 else { return out }
        pending = pending.subdata(in: (pending.startIndex + 2)..<pending.endIndex)
        state = .size
      case .trailer:
        done = true
        return out
      }
    }
  }
}
