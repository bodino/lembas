// Private borrowing: the agent's side of a borrowed request with a spliced token record.
//
// With the "Private borrowing" switch on, a borrowed request does not go to the pool
// as HTTP. Instead the agent opens a WebSocket to the pool's /pool/borrow, the pool
// names a donor and bridges the socket to its `lembas-mpc pool` helper, and this agent
// bridges the other end to `lembas-mpc borrower`. This side runs the TLS session to
// Anthropic and holds its keys alone; the pool's helper relays the bytes and writes the
// one record that carries the token, computed so that it never sees the keys and this
// side never sees the token (see docs/mpc-tls.md). The pool cannot read the request or
// the answer, so the agent tells it what happened at the end: usage to meter, or a
// usage limit so it parks that donor.

import Foundation

// Built by ./build.sh and installed next to the agent by the app; the launchd job can
// point elsewhere (tests).
let mpcHelperPath = env["LEMBAS_MPC_HELPER"]
  ?? URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
    .deletingLastPathComponent().appendingPathComponent("lembas-mpc").path
// Test hook: borrow every /v1/ request, as if the native login had just hit its limit.
let forcePool = env["LEMBAS_AGENT_FORCE_POOL"] == "1"

let anthropicHost = "api.anthropic.com"
// Headers the agent never forwards into the template; the pool's relay drops the same.
let templateDropHeaders: Set<String> = ["host", "connection", "content-length", "authorization", "x-api-key",
                                        "accept-encoding", "transfer-encoding", "expect"]
// lembas-mpc's MAX_HEADER_LEN for the pool's record (request line through the
// Authorization line), less the alignment padding it may add. The other headers follow
// in a record this side encrypts alone, so they cost nothing in MPC.
let maxHiddenBytes = 320 - 16

// Re-read per borrow, so the switch in the app takes effect without restarting the agent.
func currentConfig() -> AgentConfig? {
  FileManager.default.contents(atPath: configPath).flatMap { try? JSONDecoder().decode(AgentConfig.self, from: $0) }
}

enum PrivateBorrowError: Error, CustomStringConvertible {
  case pool(String), helper(String), template(String)
  var description: String {
    switch self {
    case .pool(let m): return "pool: \(m)"
    case .helper(let m): return "helper: \(m)"
    case .template(let m): return "request: \(m)"
    }
  }
}

enum PrivateOutcome {
  case served // the response reached Claude Code, whatever its status
  case donorExhausted(String) // that donor's token hit a limit or is dead; try the next
}

extension Agent {
  // Up to three donors; the pool picks each one and is told which to skip.
  func tryPrivate(_ req: HTTPRequest, _ out: HTTPResponder) async -> Bool {
    guard let pool else { return false }
    var exclude: [String] = []
    for _ in 0..<3 {
      do {
        let borrow = try PrivateBorrow(pool: pool, poolToken: poolToken, request: req, exclude: exclude)
        switch try await borrow.run(out, agent: self) {
        case .served: return true
        case .donorExhausted(let owner): exclude.append(owner)
        }
      } catch {
        log("private borrow failed: \(error)")
        return false
      }
    }
    return false
  }
}

final class PrivateBorrow {
  private let request: HTTPRequest
  private let model: String?
  private let dir: URL
  private let templateURL: URL
  private let bodyURL: URL
  private let fifoPath: String
  private let ws: URLSessionWebSocketTask
  private let helper = Process()

  init(pool: String, poolToken: String, request: HTTPRequest, exclude: [String]) throws {
    self.request = request
    model = modelName(request.body)
    let template = try PrivateBorrow.template(for: request)

    // The request lives briefly in a private temp folder: template and body as files
    // the helper reads, and a FIFO it streams the response into.
    let fm = FileManager.default
    dir = fm.temporaryDirectory.appendingPathComponent("lembas-borrow-\(UUID().uuidString)")
    try fm.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    templateURL = dir.appendingPathComponent("request.http")
    bodyURL = dir.appendingPathComponent("body")
    fifoPath = dir.appendingPathComponent("response").path
    try Data(template.utf8).write(to: templateURL)
    try request.body.write(to: bodyURL)
    for file in [templateURL, bodyURL] { try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: file.path) }
    guard mkfifo(fifoPath, 0o600) == 0 else { throw PrivateBorrowError.helper("mkfifo: \(String(cString: strerror(errno)))") }

    guard var parts = URLComponents(string: pool + "/pool/borrow") else { throw PrivateBorrowError.pool("bad pool URL") }
    parts.scheme = parts.scheme == "https" ? "wss" : "ws"
    if !exclude.isEmpty { parts.queryItems = [URLQueryItem(name: "exclude", value: exclude.joined(separator: ","))] }
    var wsRequest = URLRequest(url: parts.url!)
    wsRequest.setValue("Bearer \(poolToken)", forHTTPHeaderField: "authorization")
    ws = session.webSocketTask(with: wsRequest)
    ws.maximumMessageSize = 64 << 20
  }

  // The header lembas sends on a borrowed request, with holes for the token and the
  // body length. Same policy as the pool's relay: Claude Code's headers minus the
  // per-hop ones, the two beta flags a subscription token needs, a Claude Code user
  // agent, no compression. The pool's helper checks the token hole is exactly the
  // Authorization value and Host is Anthropic. Authorization comes right after
  // Content-Length: everything up to it goes in the pool's record, byte by costly byte.
  static func template(for request: HTTPRequest) throws -> String {
    let hidden = "\(request.method) \(request.path) HTTP/1.1\r\nHost: \(anthropicHost)\r\n" +
      "Content-Length: {body_len}\r\nAuthorization: Bearer {token}\r\n"
    guard hidden.utf8.count <= maxHiddenBytes else {
      throw PrivateBorrowError.template("request line too long for private borrowing (\(hidden.utf8.count) bytes)")
    }
    var text = hidden + "Connection: close\r\n"
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
    text += "anthropic-beta: \(betas.joined(separator: ","))\r\nuser-agent: \(userAgent)\r\naccept-encoding: identity\r\n\r\n"
    return text
  }

  func run(_ out: HTTPResponder, agent: Agent) async throws -> PrivateOutcome {
    defer { cleanup() }
    ws.resume()

    // 1. The pool names the donor, or says why it can't lend.
    guard case .string(let first) = try await ws.receive(),
          let hello = try? JSONSerialization.jsonObject(with: Data(first.utf8)) as? [String: Any] else {
      throw PrivateBorrowError.pool("expected the donor's name first")
    }
    guard hello["type"] as? String == "donor", let owner = hello["owner"] as? String else {
      throw PrivateBorrowError.pool("\(hello["code"] ?? "error"): \(hello["message"] ?? first)")
    }
    log("private borrow: \(owner) lends; \(request.method) \(request.path) (\(request.body.count) bytes)")

    // 2. The helper. Its stdin/stdout are the link to the pool; the response comes
    //    out of the FIFO; its logs join ours.
    helper.executableURL = URL(fileURLWithPath: mpcHelperPath)
    helper.arguments = ["borrower", "--stdio", "--output", fifoPath, "--server-name", anthropicHost,
                        "--template", templateURL.path, "--body", bodyURL.path]
    helper.environment = ["RUST_LOG": env["LEMBAS_MPC_LOG"] ?? "warn"]
    let toHelper = Pipe(), fromHelper = Pipe()
    helper.standardInput = toHelper
    helper.standardOutput = fromHelper
    helper.standardError = FileHandle.standardError
    // Opening the FIFO blocks until the helper opens its end. If the helper dies
    // first, open the write end ourselves for a moment so the reader sees EOF.
    let fifoPath = self.fifoPath
    helper.terminationHandler = { _ in
      for _ in 0..<50 {
        let fd = open(fifoPath, O_WRONLY | O_NONBLOCK)
        if fd >= 0 { close(fd); return }
        usleep(20_000)
      }
    }
    let fifoOpen = Task.detached { open(fifoPath, O_RDONLY) }
    do { try helper.run() } catch { throw PrivateBorrowError.helper("could not start \(mpcHelperPath): \(error.localizedDescription)") }
    out.whenClosed { [helper] in if helper.isRunning { helper.terminate() } }

    // 3. The bridge: pool → helper and helper → pool, until either side is done.
    let ws = self.ws
    let helper = self.helper
    let inbound = Task {
      let stdin = toHelper.fileHandleForWriting
      defer { try? stdin.close() }
      while true {
        switch try await ws.receive() {
        case .data(let data):
          // Frames for a helper that has already finished are late by definition.
          if helper.isRunning { try stdin.write(contentsOf: data) }
        case .string(let text): throw PrivateBorrowError.pool(text) // the pool only speaks up when something failed
        @unknown default: break
        }
      }
    }
    let outbound = Task {
      for await chunk in chunks(of: fromHelper.fileHandleForReading) { try await ws.send(.data(chunk)) }
    }

    // 4. The response, as the helper decrypts it.
    let fd = await fifoOpen.value
    guard fd >= 0 else { throw PrivateBorrowError.helper("could not open the response pipe") }
    var response = HTTPResponseReader(chunks(of: FileHandle(fileDescriptor: fd, closeOnDealloc: true)))
    let head: HTTPURLResponse
    do {
      head = try await response.head(url: URL(string: "https://\(anthropicHost)\(request.path)")!)
    } catch {
      // No response at all: the pool's side failed, and its text frame says why.
      inbound.cancel()
      if case .failure(let poolError) = await inbound.result, let poolError = poolError as? PrivateBorrowError { throw poolError }
      throw error
    }

    let outcome: PrivateOutcome
    let tap = UsageTap(contentType: head.value(forHTTPHeaderField: "content-type"))
    if head.statusCode == 429 || head.statusCode == 401 {
      // Decide before answering Claude Code: a limit on this donor means another donor.
      var body = Data()
      for try await chunk in response.body { body.append(chunk) }
      let text = String(decoding: body, as: UTF8.self)
      if head.statusCode == 401 {
        log("private borrow: \(owner)'s token is dead (401)")
        report(["type": "dead", "status": 401, "model": model as Any])
        outcome = .donorExhausted(owner)
      } else if isUsageLimit(head, text) {
        let seconds = retryAfterSeconds(head) ?? defaultLimitSeconds
        log("private borrow: \(owner)'s token hit its limit: \(describeLimit(head, text))")
        report(["type": "limit", "status": 429, "forMs": Int(seconds * 1000), "model": model as Any])
        outcome = .donorExhausted(owner)
      } else {
        await agent.sendFixed(out, head, body) // transient rate limit: Claude Code retries
        report(["type": "result", "status": 429, "usd": 0, "model": model as Any])
        outcome = .served
      }
    } else {
      await out.start(status: head.statusCode, headers: agent.responseHeaders(head))
      var pending = Data()
      do {
        for try await chunk in response.body {
          pending.append(chunk)
          if pending.last == 0x0A || pending.count >= 16 << 10 {
            tap.push(pending)
            guard await out.chunk(pending) else { break }
            pending.removeAll(keepingCapacity: true)
          }
        }
      } catch {
        if !out.closed { log("private borrow: response ended early: \(error)") }
      }
      tap.push(pending)
      await out.chunk(pending)
      await out.end()
      let usd = costUsd(model: model, usage: tap.finish())
      report(["type": "result", "status": head.statusCode, "usd": usd, "model": model as Any])
      outcome = .served
    }

    // 5. Let the helpers finish their close, then drop the socket.
    _ = await outbound.result
    inbound.cancel()
    await waitForExit()
    ws.cancel(with: .normalClosure, reason: nil)
    return outcome
  }

  private func report(_ object: [String: Any]) {
    let clean = object.filter { !($0.value is NSNull) }
    guard let data = try? JSONSerialization.data(withJSONObject: clean) else { return }
    ws.send(.string(String(decoding: data, as: UTF8.self))) { _ in }
  }

  private func waitForExit() async {
    for _ in 0..<100 where helper.isRunning { try? await Task.sleep(nanoseconds: 50_000_000) }
    if helper.isRunning { helper.terminate() }
  }

  private func cleanup() {
    if helper.isRunning { helper.terminate() }
    ws.cancel(with: .goingAway, reason: nil)
    try? FileManager.default.removeItem(at: dir)
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
        guard let size = Int(line.split(separator: ";").first.map(String.init) ?? "", radix: 16) else {
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
