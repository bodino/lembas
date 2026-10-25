// Links a member's claude.ai subscription to the pool (port of installer/login.mjs).
// OAuth with PKCE against Claude Code's client: the browser login happens between the
// member and Anthropic; the pool only receives tokens scoped user:inference +
// user:profile, so it can route borrowed requests and read usage windows.

import AppKit
import CryptoKit
import Foundation

enum SubscriptionLogin {
  static let clientID = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
  static let port: UInt16 = 8912

  static func run(pool: String, poolToken: String) async throws {
    let verifier = base64url(randomBytes(32))
    let challenge = base64url(Data(SHA256.hash(data: Data(verifier.utf8))))
    let state = randomBytes(16).map { String(format: "%02x", $0) }.joined()
    let redirectURI = "http://localhost:\(port)/callback"
    var auth = URLComponents(string: "https://claude.ai/oauth/authorize")!
    auth.queryItems = [
      URLQueryItem(name: "response_type", value: "code"),
      URLQueryItem(name: "client_id", value: clientID),
      URLQueryItem(name: "redirect_uri", value: redirectURI),
      URLQueryItem(name: "scope", value: "user:inference user:profile"),
      URLQueryItem(name: "code_challenge", value: challenge),
      URLQueryItem(name: "code_challenge_method", value: "S256"),
      URLQueryItem(name: "state", value: state),
    ]

    let result = ResultBox()
    let attempt = Attempt(verifier: verifier, state: state, redirectURI: redirectURI, pool: pool, poolToken: poolToken)
    let html = [("Content-Type", "text/html; charset=utf-8")]
    // Stays up until the subscription is connected (or we time out), so a failed attempt
    // can be retried from the browser instead of leaving the person stuck.
    let server = try await listen { req, out in
      guard let url = URLComponents(string: "http://localhost\(req.path)"), url.path == "/callback" else {
        return await out.send(status: 404)
      }
      let query = Dictionary((url.queryItems ?? []).map { ($0.name, $0.value ?? "") }, uniquingKeysWith: { a, _ in a })
      do {
        guard let code = query["code"], query["state"] == state else { throw LoginError("the login was not approved") }
        try await attempt.complete(code: code)
        await out.send(status: 200, headers: html,
                       body: page(ok: true, "Subscription connected", "lembas can now lend and borrow for you. You can close this tab."))
        result.finish(nil)
      } catch {
        FileHandle.standardError.write(Data("[lembas] connecting subscription failed: \(error)\n".utf8))
        // Retry with the tokens we already have, or sign in again if we never got any.
        let retry = await attempt.hasTokens ? "javascript:location.reload()" : auth.url!.absoluteString
        await out.send(status: 500, headers: html,
                       body: page(ok: false, "Couldn't connect", sentence(error.localizedDescription), retry: retry))
      }
    }
    defer { server.stop() }
    NSWorkspace.shared.open(auth.url!)
    try await result.wait(timeout: 600)
  }

  // One login: Anthropic's code can be exchanged only once, so the tokens are kept and
  // only the hand-off to the pool is retried. Serialized, because browsers sometimes
  // load the callback twice; once connected, later loads just succeed.
  private actor Attempt {
    let verifier: String, state: String, redirectURI: String, pool: String, poolToken: String
    private var tokens: (access: String, refresh: String, expiresAt: Int)?
    private var done = false

    init(verifier: String, state: String, redirectURI: String, pool: String, poolToken: String) {
      (self.verifier, self.state, self.redirectURI, self.pool, self.poolToken) = (verifier, state, redirectURI, pool, poolToken)
    }

    var hasTokens: Bool { tokens != nil }

    func complete(code: String) async throws {
      if done { return }
      if tokens == nil { tokens = try await exchange(code: code) }
      try await deposit(tokens!)
      done = true
    }

    private func exchange(code: String) async throws -> (String, String, Int) {
      var request = URLRequest(url: URL(string: "https://platform.claude.com/v1/oauth/token")!)
      request.httpMethod = "POST"
      request.setValue("application/json", forHTTPHeaderField: "content-type")
      request.httpBody = try JSONSerialization.data(withJSONObject: [
        "grant_type": "authorization_code", "code": code, "redirect_uri": redirectURI,
        "client_id": SubscriptionLogin.clientID, "code_verifier": verifier, "state": state,
      ])
      let (data, _) = try await URLSession.shared.data(for: request)
      let body = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
      guard let access = body["access_token"] as? String, let refresh = body["refresh_token"] as? String else {
        throw LoginError("Anthropic didn't accept the login")
      }
      let expiresIn = (body["expires_in"] as? NSNumber)?.doubleValue ?? 3600
      return (access, refresh, Int((Date().timeIntervalSince1970 + expiresIn) * 1000))
    }

    private func deposit(_ tokens: (access: String, refresh: String, expiresAt: Int)) async throws {
      var put = URLRequest(url: URL(string: pool + "/pool/tokens")!)
      put.httpMethod = "PUT"
      put.timeoutInterval = 15
      put.setValue("application/json", forHTTPHeaderField: "content-type")
      put.setValue("Bearer \(poolToken)", forHTTPHeaderField: "authorization")
      put.httpBody = try JSONSerialization.data(withJSONObject: [
        "accessToken": tokens.access, "refreshToken": tokens.refresh, "expiresAt": tokens.expiresAt,
      ])
      do {
        let (_, response) = try await URLSession.shared.data(for: put)
        guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw LoginError("the pool didn't accept the login") }
      } catch let error as URLError {
        throw LoginError("couldn't reach the pool (\(error.localizedDescription))")
      }
    }
  }


  // Same look as the menu bar app: system blue accent, neutral card, light and dark.
  // A cancelled attempt (Retry) may still be releasing the port; give it a moment.
  private static func listen(_ handler: @escaping HTTPServer.Handler) async throws -> HTTPServer {
    for attempt in 1...10 {
      do { return try await HTTPServer(port: port, handler: handler) } catch where attempt < 10 {
        try await Task.sleep(nanoseconds: 200_000_000)
      }
    }
    throw LoginError("the login port is busy")
  }

  private static func page(ok: Bool, _ title: String, _ message: String, retry: String? = nil) -> Data {
    func escape(_ text: String) -> String {
      text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;")
    }
    let badge = LembasLogo.tilePNG(pixels: 66)?.base64EncodedString() ?? ""
    let icon = ok
      ? ##"<path d="M7 12.5l3.2 3.2L17 9" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/>"##
      : ##"<path d="M12 7v6M12 16.5v.5" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round"/>"##
    return Data("""
      <!doctype html>
      <html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
      <title>lembas</title>
      <style>
        :root { --bg: #f5f5f7; --card: #fff; --line: rgba(0,0,0,.08); --text: #1d1d1f; --muted: #6e6e73;
                --accent: #007aff; --status: \(ok ? "var(--accent)" : "#ff9500"); color-scheme: light dark; }
        @media (prefers-color-scheme: dark) {
          :root { --bg: #1c1c1e; --card: #2c2c2e; --line: rgba(255,255,255,.08); --text: #f5f5f7;
                  --muted: #98989d; --accent: #0a84ff; }
        }
        * { box-sizing: border-box; margin: 0; }
        body { min-height: 100vh; display: grid; place-items: center; padding: 24px; background: var(--bg);
               color: var(--text); font: 15px/1.45 -apple-system, BlinkMacSystemFont, "SF Pro Text", sans-serif; }
        .card { width: 100%; max-width: 360px; padding: 32px 28px 28px; text-align: center; background: var(--card);
                border: 1px solid var(--line); border-radius: 16px; box-shadow: 0 8px 30px rgba(0,0,0,.06); }
        .brand { display: inline-flex; align-items: center; gap: 8px; font-weight: 600; font-size: 13px; color: var(--muted); }
        .badge { width: 22px; height: 22px; }
        .status { width: 56px; height: 56px; margin: 28px auto 16px; border-radius: 50%; display: grid; place-items: center;
                  background: linear-gradient(color-mix(in srgb, var(--status) 85%, #fff), var(--status)); }
        h1 { font-size: 19px; font-weight: 600; letter-spacing: -.01em; }
        p { margin-top: 6px; color: var(--muted); min-height: 2.9em; }
        .button { display: block; margin-top: 18px; padding: 8px 14px; border-radius: 8px; background: var(--accent);
                  color: #fff; font-weight: 500; text-decoration: none; }
      </style></head>
      <body><main class="card">
        <div class="brand"><img class="badge" alt="" src="data:image/png;base64,\(badge)">lembas</div>
        <div class="status"><svg width="36" height="36" viewBox="0 0 24 24">\(icon)</svg></div>
        <h1>\(escape(title))</h1>
        <p>\(escape(message))</p>
        \(retry.map { #"<a class="button" href="\#($0.replacingOccurrences(of: "\"", with: "&quot;"))">Try again</a>"# } ?? "")
      </main></body></html>
      """.utf8)
  }

  private static func sentence(_ text: String) -> String {
    let trimmed = text.trimmingCharacters(in: .whitespaces)
    return trimmed.prefix(1).uppercased() + trimmed.dropFirst() + (trimmed.hasSuffix(".") ? "" : ".")
  }

  private static func randomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    return Data(bytes)
  }

  private static func base64url(_ data: Data) -> String {
    data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
      .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
  }
}

struct LoginError: LocalizedError {
  let errorDescription: String?
  init(_ message: String) { errorDescription = message }
}

// Hands the callback's outcome to the waiting login, or times out.
private final class ResultBox {
  private let lock = NSLock()
  private var outcome: Error??
  private var waiter: CheckedContinuation<Void, Error>?

  func finish(_ error: Error?) {
    let waiter = lock.withLock { () -> CheckedContinuation<Void, Error>? in
      guard outcome == nil else { return nil }
      outcome = .some(error)
      defer { self.waiter = nil }
      return self.waiter
    }
    if let error { waiter?.resume(throwing: error) } else { waiter?.resume() }
  }

  func wait(timeout: TimeInterval) async throws {
    Task {
      try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
      finish(LoginError("timed out waiting for the browser")) // no-op if already finished
    }
    // Cancelling the task (Retry in the app) ends the wait, which stops the callback server.
    try await withTaskCancellationHandler {
      try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
        let done = lock.withLock { () -> Error?? in
          if outcome == nil { waiter = cont }
          return outcome
        }
        if let done {
          if let error = done { cont.resume(throwing: error) } else { cont.resume() }
        }
      }
    } onCancel: {
      finish(CancellationError())
    }
  }
}
