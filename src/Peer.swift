// The peer: this Mac's place in a circle, run by the agent as a child process
// (`lembas-mpc peer`, docs/p2p.md). It lends this Mac's login to the members its owner
// chose and borrows from theirs, Mac to Mac over iroh, with no pool. The agent drives
// it over JSON lines on its stdin/stdout (commands and a status event every half
// minute) and sends borrowed requests to the Unix socket it serves.
//
// The login the peer lends and proves with sits in a file the agent keeps fresh
// (`LoginFile`): the peer re-reads it at each use, so a refreshed token needs no restart.

import Foundation

let loginPath = env["LEMBAS_LOGIN"] ?? home.appendingPathComponent(".config/lembas-login.json").path

// Where the peer keeps its key, circle and settings: next to the agent's own copy.
let peerDir = env["LEMBAS_PEER_DIR"]
  ?? URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().appendingPathComponent("peer").path

struct PeerError: Error, CustomStringConvertible {
  let description: String
  init(_ message: String) { description = message }
}

// The claude.ai login as the app deposits it: Claude Code's OAuth tokens.
enum LoginFile {
  struct Tokens: Codable {
    var accessToken: String
    var refreshToken: String
    var expiresAt: Int // ms since the epoch
  }

  static func read() -> Tokens? {
    FileManager.default.contents(atPath: loginPath).flatMap { try? JSONDecoder().decode(Tokens.self, from: $0) }
  }

  static func write(_ tokens: Tokens) throws {
    let url = URL(fileURLWithPath: loginPath)
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try JSONEncoder().encode(tokens).write(to: url, options: .atomic)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: loginPath)
  }

  // Claude Code's OAuth client; the pool used to do this refresh for every member.
  static let clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"

  // Refreshes the access token when it is about to expire. Returns whether it did.
  static func refreshIfNeeded() async -> Bool {
    guard let tokens = read() else { return false }
    let left = Double(tokens.expiresAt) / 1000 - Date().timeIntervalSince1970
    guard left < 15 * 60 else { return false }
    var request = URLRequest(url: URL(string: "https://platform.claude.com/v1/oauth/token")!)
    request.httpMethod = "POST"
    request.timeoutInterval = 20
    request.setValue("application/json", forHTTPHeaderField: "content-type")
    request.httpBody = try? JSONSerialization.data(withJSONObject: [
      "grant_type": "refresh_token", "refresh_token": tokens.refreshToken, "client_id": clientID,
    ])
    guard let (data, response) = try? await session.data(for: request),
          let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
      log("login refresh: no answer from Anthropic")
      return false
    }
    guard (response as? HTTPURLResponse)?.statusCode == 200, let access = body["access_token"] as? String else {
      log("login refresh failed: \(String(decoding: data.prefix(200), as: UTF8.self))")
      return false
    }
    let expiresIn = (body["expires_in"] as? NSNumber)?.doubleValue ?? 3600
    let fresh = Tokens(accessToken: access, refreshToken: body["refresh_token"] as? String ?? tokens.refreshToken,
                       expiresAt: Int((Date().timeIntervalSince1970 + expiresIn) * 1000))
    do {
      try write(fresh)
      log("login refreshed; valid for \(Int(expiresIn / 60)) min")
      return true
    } catch {
      log("login refresh: could not write \(loginPath): \(error.localizedDescription)")
      return false
    }
  }
}

// One peer process, restarted when it dies, with its control channel.
actor PeerProcess {
  let name: String
  let socketDir: URL
  var socketPath: String { socketDir.appendingPathComponent("s").path }

  private var process: Process?
  private var stdin: FileHandle?
  private var reader: Task<Void, Never>?
  private var waiting: [CheckedContinuation<Any, Error>] = []
  private var stopped = false
  private(set) var status: [String: Any]?
  private(set) var statusAt = Date.distantPast
  private(set) var lastEvent: [String: Any]?

  init(name: String) {
    self.name = name
    // Short: a Unix socket path must fit in 104 bytes.
    socketDir = FileManager.default.temporaryDirectory.appendingPathComponent("lembas-p\(UUID().uuidString.prefix(6))")
  }

  func start() {
    guard !stopped, process == nil else { return }
    let fm = FileManager.default
    try? fm.createDirectory(at: socketDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try? fm.createDirectory(atPath: peerDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    let p = Process()
    p.executableURL = URL(fileURLWithPath: mpcHelperPath)
    p.arguments = ["peer", "--dir", peerDir, "--name", name, "--token-file", loginPath, "--control", "--socket", socketPath]
    p.environment = ["RUST_LOG": env["LEMBAS_MPC_LOG"] ?? "lembas_mpc=info", "HOME": home.path]
    let toPeer = Pipe(), fromPeer = Pipe()
    p.standardInput = toPeer
    p.standardOutput = fromPeer
    p.standardError = FileHandle.standardError
    p.terminationHandler = { proc in
      Task { await self.ended(code: proc.terminationStatus) }
    }
    do {
      try p.run()
    } catch {
      log("peer: could not start \(mpcHelperPath): \(error.localizedDescription)")
      scheduleRestart()
      return
    }
    process = p
    stdin = toPeer.fileHandleForWriting
    log("peer: started (pid \(p.processIdentifier)), socket \(socketPath)")
    reader = Task { [weak self] in
      var buffer = Data()
      for await chunk in chunks(of: fromPeer.fileHandleForReading) {
        buffer.append(chunk)
        while let nl = buffer.firstIndex(of: 0x0A) {
          let line = buffer[buffer.startIndex..<nl]
          buffer.removeSubrange(buffer.startIndex...nl)
          guard let obj = (try? JSONSerialization.jsonObject(with: line)) as? [String: Any] else { continue }
          await self?.received(obj)
        }
      }
    }
  }

  private func received(_ obj: [String: Any]) {
    if let event = obj["event"] as? String {
      lastEvent = obj
      if event == "status", let s = obj["status"] as? [String: Any] {
        status = s
        statusAt = Date()
      }
      return
    }
    guard !waiting.isEmpty else { return }
    let cont = waiting.removeFirst()
    if obj["ok"] as? Bool == true {
      // A command that answers with the status (join, sync, found) refreshes the cache.
      if let s = obj["result"] as? [String: Any], s["members"] != nil {
        status = s
        statusAt = Date()
      }
      cont.resume(returning: obj["result"] ?? NSNull())
    } else {
      cont.resume(throwing: PeerError(obj["error"] as? String ?? "the peer refused"))
    }
  }

  private func ended(code: Int32) {
    log("peer: exited (\(code))")
    process = nil
    stdin = nil
    reader?.cancel()
    let pending = waiting
    waiting = []
    for cont in pending { cont.resume(throwing: PeerError("the peer stopped")) }
    scheduleRestart()
  }

  private func scheduleRestart() {
    guard !stopped else { return }
    Task {
      try? await Task.sleep(nanoseconds: 2_000_000_000)
      await self.start()
    }
  }

  var running: Bool { process?.isRunning == true }

  // One command, answered in order (the peer handles them one at a time).
  func command(_ obj: [String: Any]) async throws -> Any {
    guard let stdin, running else { throw PeerError("the peer is not running") }
    let data = try JSONSerialization.data(withJSONObject: obj)
    try stdin.write(contentsOf: data + Data([0x0A]))
    statusAt = .distantPast
    return try await withTimeout(60, "the peer's answer") {
      try await withCheckedThrowingContinuation { cont in
        Task { await self.enqueue(cont) }
      }
    }
  }

  private func enqueue(_ cont: CheckedContinuation<Any, Error>) {
    waiting.append(cont)
  }

  // A fresh status, asking the peer unless the last event is recent.
  func currentStatus(maxAge: TimeInterval = 1) async throws -> [String: Any] {
    if let status, Date().timeIntervalSince(statusAt) < maxAge { return status }
    guard let s = try await command(["cmd": "status"]) as? [String: Any] else { throw PeerError("bad status") }
    status = s
    statusAt = Date()
    return s
  }

  func stop() {
    stopped = true
    reader?.cancel()
    if let process, process.isRunning { process.terminate() }
    try? FileManager.default.removeItem(at: socketDir)
  }
}
