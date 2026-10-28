// Borrowed requests, privately: each one goes to the peer's local socket and from
// there to a friend's Mac as a spliced token record (docs/mpc-tls.md, docs/p2p.md).
// The friend's Mac inserts the one record carrying its token; it can read nothing
// else, and this Mac never sees the token.

import Foundation

// The helper that runs the peer, next to the agent (the app copies it there).
let mpcHelperPath = env["LEMBAS_MPC_HELPER"]
  ?? URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().appendingPathComponent("lembas-mpc").path
// Test hook: send every inference request through the circle, limit or not.
let forcePool = env["LEMBAS_AGENT_FORCE_POOL"] == "1"

let anthropicHost = "api.anthropic.com"
// Headers that don't go into the borrowed request's head.
let templateDropHeaders: Set<String> = ["host", "connection", "content-length", "authorization", "x-api-key",
                                        "accept-encoding", "transfer-encoding", "expect", "x-lembas-request"]
// The lender's record holds the request line, Host, Content-Length and the Authorization
// line, at most lembas-mpc's MAX_HEADER_LEN with the token span aligned.
let maxRequestLine = 110

func currentConfig() -> AgentConfig? {
  FileManager.default.contents(atPath: configPath).flatMap { try? JSONDecoder().decode(AgentConfig.self, from: $0) }
}

enum PrivateBorrowError: Error, CustomStringConvertible {
  case peer(String), helper(String), template(String)
  var description: String {
    switch self {
    case .peer(let m): return "circle: \(m)"
    case .helper(let m): return "helper: \(m)"
    case .template(let m): return "request: \(m)"
    }
  }
}

/// How a private attempt ended, for the agent to decide what comes next.
enum PrivateAttempt {
  case served // the response reached Claude Code, whatever its status
  case failed // nobody could lend, or the private path failed; borrowing pauses
}

enum PrivateOutcome {
  case served // the response reached Claude Code, whatever its status
  case lenderExhausted // that lender's token hit a limit or is dead
}

extension Agent {
  // The peer picks a lender per request; a lender whose token is spent is tried past
  // once (its own usage read parks it within the minute).
  func tryPrivate(_ req: HTTPRequest, _ out: HTTPResponder) async -> PrivateAttempt {
    guard let peer else { return .failed }
    guard await peer.running else {
      log("private borrow: the peer is not running")
      return .failed
    }
    let socket = await peer.socketPath
    for attempt in 0..<2 {
      do {
        switch try await borrowThrough(socket, req, out) {
        case .served: return .served
        case .lenderExhausted:
          if attempt < 1 { try? await Task.sleep(nanoseconds: 300_000_000) }
        }
      } catch {
        log("private borrow failed: \(error)")
        return .failed
      }
    }
    return .failed
  }

  // One request through the peer's local socket.
  func borrowThrough(_ socketPath: String, _ request: HTTPRequest, _ out: HTTPResponder) async throws -> PrivateOutcome {
    let model = modelName(request.body)
    var bytes = Data(try BorrowRequest.head(for: request).utf8)
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
      let url = URL(string: "https://\(anthropicHost)\(request.path)") ?? URL(string: "https://\(anthropicHost)/")!
      head = try await withTimeout(responseHeadTimeout, "the response head", onTimeout: { _ = Darwin.shutdown(fd, SHUT_RDWR) }, {
        try await response.head(url: url)
      })
    } catch {
      writer.cancel()
      throw error
    }
    _ = try await writer.value

    // The peer's own answers: nobody lending (503) or a failure (502).
    if let kind = head.value(forHTTPHeaderField: "x-lembas-error") {
      var body = Data()
      for try await chunk in response.body { body.append(chunk) }
      let message = (try? JSONSerialization.jsonObject(with: body) as? [String: Any])
        .flatMap { ($0["error"] as? [String: Any])?["message"] as? String } ?? String(decoding: body, as: UTF8.self)
      throw kind == "refused" ? PrivateBorrowError.peer("refused: \(message)") : PrivateBorrowError.helper(message)
    }
    let reqNo = head.value(forHTTPHeaderField: "x-lembas-request").flatMap(Int.init) ?? 0
    log("private borrow: request \(reqNo) \(request.method) \(request.path) (\(request.body.count) bytes) → \(head.statusCode)")

    let tap = UsageTap(contentType: head.value(forHTTPHeaderField: "content-type"))
    if head.statusCode == 429 || head.statusCode == 401 {
      // Decide before answering Claude Code: a limit on this lender means another lender.
      var body = Data()
      for try await chunk in response.body { body.append(chunk) }
      let text = String(decoding: body, as: UTF8.self)
      if head.statusCode == 401 {
        log("private borrow: the lender's token is dead (401)")
        return .lenderExhausted
      }
      if isUsageLimit(head, text) {
        log("private borrow: the lender's token hit its limit: \(describeLimit(head, text))")
        return .lenderExhausted
      }
      await sendFixed(out, head, body) // transient rate limit: Claude Code retries
      return .served
    }
    var headers = responseHeaders(head)
    headers = headers.filter { $0.0.lowercased() != "x-lembas-request" }
    await out.start(status: head.statusCode, headers: headers)
    var pending = Data()
    do {
      for try await chunk in response.body {
        pending.append(chunk)
        if pending.last == 0x0A || pending.count >= 16 << 10 {
          tap.push(pending)
          let delivered = await out.chunk(pending)
          pending.removeAll(keepingCapacity: true)
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
    log("private borrow: request \(reqNo) \(model ?? "request") ~$\(String(format: "%.4f", usd))")
    return .served
  }
}

enum BorrowRequest {
  // The request as the helper wants it: plain HTTP/1.1 with Content-Length. Claude
  // Code's headers minus the per-hop ones, the two beta flags a subscription token
  // needs, a Claude Code user agent, no compression. The helper puts the request
  // line, Host, Content-Length and the Authorization line in the lender's record.
  static func head(for request: HTTPRequest) throws -> String {
    guard !request.method.isEmpty, request.method.utf8.allSatisfy({ $0 >= 0x41 && $0 <= 0x5a }),
          request.path.hasPrefix("/"), request.path.utf8.allSatisfy(urlPathByte),
          URL(string: "https://\(anthropicHost)\(request.path)") != nil else {
      throw PrivateBorrowError.template("bad request line")
    }
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
}

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
