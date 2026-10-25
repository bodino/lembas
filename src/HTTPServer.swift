// Minimal HTTP/1.1 server on 127.0.0.1, shared by the lembas agent and the menu bar
// app's subscription login callback. One request per connection (every response says
// Connection: close), which is all Claude Code and a browser redirect need.

import Foundation
import Network

struct HTTPRequest {
  var method: String
  var path: String
  var headers: [(name: String, value: String)] // names lowercased, in arrival order
  var body: Data

  func header(_ name: String) -> String? { headers.first { $0.name == name }?.value }
}

enum HTTPError: Error {
  case closed, tooLarge, malformed
}

// Shared between the connection's callbacks and the handler; its state is behind `lock`.
final class HTTPResponder: @unchecked Sendable {
  private let connection: NWConnection
  private let lock = NSLock()
  private var _closed = false
  private var onClose: [() -> Void] = []

  // True once the client has gone away (or the response is finished).
  var closed: Bool { lock.withLock { _closed } }

  init(_ connection: NWConnection) {
    self.connection = connection
  }

  // Runs `action` when the client disconnects, e.g. to cancel an upstream request.
  func whenClosed(_ action: @escaping () -> Void) {
    let already = lock.withLock { () -> Bool in
      if _closed { return true }
      onClose.append(action)
      return false
    }
    if already { action() }
  }

  func markClosed() {
    let actions = lock.withLock { () -> [() -> Void] in
      if _closed { return [] }
      _closed = true
      defer { onClose = [] }
      return onClose
    }
    actions.forEach { $0() }
  }

  // A complete response with a known length.
  func send(status: Int, headers: [(String, String)] = [], body: Data = Data()) async {
    await write(head(status, headers + [("Content-Length", String(body.count))]) + body)
    finish()
  }

  func sendJSON(status: Int, _ object: [String: Any]) async {
    let body = (try? JSONSerialization.data(withJSONObject: object)) ?? Data()
    await send(status: status, headers: [("Content-Type", "application/json")], body: body)
  }

  // A streamed response: start, any number of chunks, then end.
  func start(status: Int, headers: [(String, String)]) async {
    await write(head(status, headers + [("Transfer-Encoding", "chunked")]))
  }

  // Returns false once the client is gone, so the caller can stop producing.
  @discardableResult
  func chunk(_ data: Data) async -> Bool {
    if data.isEmpty { return !closed }
    await write(Data((String(data.count, radix: 16) + "\r\n").utf8) + data + Data("\r\n".utf8))
    return !closed
  }

  func end() async {
    await write(Data("0\r\n\r\n".utf8))
    finish()
  }

  private func head(_ status: Int, _ headers: [(String, String)]) -> Data {
    var text = "HTTP/1.1 \(status) \(status < 300 ? "OK" : "Status")\r\n" // clients ignore the phrase
    for (name, value) in headers { text += "\(name): \(value)\r\n" }
    text += "Connection: close\r\n\r\n"
    return Data(text.utf8)
  }

  private func write(_ data: Data) async {
    if closed { return }
    await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
      connection.send(content: data, completion: .contentProcessed { error in
        if error != nil { self.markClosed() }
        cont.resume()
      })
    }
  }

  private func finish() {
    connection.send(content: nil, contentContext: .finalMessage, isComplete: true,
                    completion: .contentProcessed { _ in self.connection.cancel() })
    markClosed()
  }
}

final class HTTPServer {
  typealias Handler = (HTTPRequest, HTTPResponder) async -> Void

  static let maxBody = 64 << 20 // Claude requests with images can be tens of MB

  private let listener: NWListener
  private let queue = DispatchQueue(label: "lembas.http", attributes: .concurrent)

  // Binds 127.0.0.1:<port> and returns once listening (throws if the port is taken).
  init(port: UInt16, handler: @escaping Handler) async throws {
    let params = NWParameters.tcp
    params.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!)
    params.allowLocalEndpointReuse = true
    listener = try NWListener(using: params)
    let queue = self.queue
    listener.newConnectionHandler = { connection in
      connection.start(queue: queue)
      Task { await HTTPServer.serve(connection, handler) }
    }
    try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
      let once = Once()
      listener.stateUpdateHandler = { state in
        switch state {
        case .ready: once.run { cont.resume() }
        case .failed(let error), .waiting(let error): once.run { cont.resume(throwing: error) }
        default: break
        }
      }
      listener.start(queue: queue)
    }
  }

  func stop() {
    listener.cancel()
  }

  private static func serve(_ connection: NWConnection, _ handler: Handler) async {
    let reader = Reader(connection)
    let responder = HTTPResponder(connection)
    connection.stateUpdateHandler = { state in
      switch state {
      case .failed, .cancelled: responder.markClosed()
      default: break
      }
    }
    do {
      let request = try await reader.request()
      // Watch for the client hanging up while we work on the response.
      connection.receive(minimumIncompleteLength: 1, maximumLength: 1) { _, _, isComplete, error in
        if isComplete || error != nil { responder.markClosed() }
      }
      await handler(request, responder)
    } catch HTTPError.tooLarge {
      await responder.send(status: 413)
    } catch HTTPError.malformed {
      await responder.send(status: 400)
    } catch {
      connection.cancel()
    }
  }
}

// Runs its closure the first time only; resuming a continuation twice would crash.
final class Once {
  private let lock = NSLock()
  private var done = false

  func run(_ action: () -> Void) {
    let first = lock.withLock { () -> Bool in
      defer { done = true }
      return !done
    }
    if first { action() }
  }
}

private let crlf = Data("\r\n".utf8)

private final class Reader {
  let connection: NWConnection
  var buffer = Data()

  init(_ connection: NWConnection) {
    self.connection = connection
  }

  func request() async throws -> HTTPRequest {
    let parts = try await line().split(separator: " ", omittingEmptySubsequences: true)
    guard parts.count >= 2 else { throw HTTPError.malformed }
    var headers: [(name: String, value: String)] = []
    while true {
      let header = try await line()
      if header.isEmpty { break }
      guard headers.count < 200, let colon = header.firstIndex(of: ":") else { throw HTTPError.malformed }
      headers.append((header[..<colon].trimmingCharacters(in: .whitespaces).lowercased(),
                      header[header.index(after: colon)...].trimmingCharacters(in: .whitespaces)))
    }
    var request = HTTPRequest(method: String(parts[0]), path: String(parts[1]), headers: headers, body: Data())
    if request.header("transfer-encoding")?.lowercased().contains("chunked") == true {
      while true {
        let sizeLine = try await line()
        guard let size = Int(sizeLine.split(separator: ";").first ?? "", radix: 16) else { throw HTTPError.malformed }
        if size == 0 {
          while try await !line().isEmpty {} // trailers
          break
        }
        guard request.body.count + size <= HTTPServer.maxBody else { throw HTTPError.tooLarge }
        request.body.append(try await bytes(size))
        _ = try await line()
      }
    } else if let length = request.header("content-length").flatMap({ Int($0) }) {
      guard length >= 0, length <= HTTPServer.maxBody else { throw HTTPError.tooLarge }
      request.body = try await bytes(length)
    }
    return request
  }

  private func fill() async throws {
    let data: Data? = try await withCheckedThrowingContinuation { cont in
      connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, isComplete, error in
        if let error { cont.resume(throwing: error) }
        else if let data, !data.isEmpty { cont.resume(returning: data) }
        else if isComplete { cont.resume(returning: nil) }
        else { cont.resume(returning: Data()) }
      }
    }
    guard let data else { throw HTTPError.closed }
    buffer.append(data)
  }

  private func line() async throws -> String {
    while true {
      if let range = buffer.range(of: crlf) {
        let text = String(decoding: buffer[buffer.startIndex..<range.lowerBound], as: UTF8.self)
        buffer = buffer.subdata(in: range.upperBound..<buffer.endIndex)
        return text
      }
      if buffer.count > 64 << 10 { throw HTTPError.tooLarge }
      try await fill()
    }
  }

  private func bytes(_ count: Int) async throws -> Data {
    while buffer.count < count { try await fill() }
    let data = buffer.subdata(in: buffer.startIndex..<buffer.startIndex + count)
    buffer = buffer.subdata(in: buffer.startIndex + count..<buffer.endIndex)
    return data
  }
}
