// lembas bar — a macOS menu bar app for the lembas pool.
// Shows your live sharing state and lets you lend to individual people.
// Config: ~/.config/lembas.json  {"url": "http://…:8787", "token": "pool-…"}

import AppKit
import Combine
import ObjectiveC
import CryptoKit
import ServiceManagement
import SwiftUI

// Which install this copy of the app manages. Normally the default one; launching it
// with LEMBAS_PROFILE=<name> runs another member side by side (e.g. testing invites on
// one Mac), with its own config, agent, port and Claude Code settings folder.
enum Profile {
  static let name: String? = ProcessInfo.processInfo.environment["LEMBAS_PROFILE"].flatMap { $0.isEmpty ? nil : $0 }
  private static let home = FileManager.default.homeDirectoryForCurrentUser
  private static let suffix = name.map { "-\($0)" } ?? ""

  static let configURL = home.appendingPathComponent(".config/lembas\(suffix).json")
  static let agentLabel = "com.lembas.agent" + (name.map { ".\($0)" } ?? "")
  static let agentPlist = home.appendingPathComponent("Library/LaunchAgents/\(agentLabel).plist")
  static let agentLog = home.appendingPathComponent("Library/Logs/lembas-agent\(suffix).log").path
  static let agentPort = name == nil ? 8788 : 8789
  // Claude Code reads CLAUDE_CONFIG_DIR; a profile's lives in ~/.claude-<name>.
  static let claudeSettings = home.appendingPathComponent(name.map { ".claude-\($0)" } ?? ".claude")
    .appendingPathComponent("settings.json")
}

struct Config: Codable {
  var url: String
  var token: String
  var agentPort: Int? // only set for profiles; the agent defaults to 8788
  // `false` forces the pool's readable relay; otherwise borrowing is private. The agent
  // re-reads this per request (src/PrivateBorrow.swift).
  var privateBorrowing: Bool?
  // Test hook for the agent: borrow every request, as if the login were at its limit.
  var pretendLimited: Bool?
}

// The pool rejected our token: we were removed, or left from another copy.
struct NotAMember: Error {}

// A newer build published as a GitHub release (see .github/workflows/release.yml).
struct AvailableUpdate {
  var version: String
  var build: Int
  var sha256: String
}

// What I lend one person: whenever I'm away, and optionally even while I'm working
// (until my 5-hour window reaches `working5h`).
struct LendingMember: Identifiable {
  var name: String
  var away: Bool
  var working: Bool
  var working5h: Double
  var id: String { name }
  var displayName: String { prettyName(name) }
  // What a save would send; used to tell whether there are unsaved edits.
  var setting: String { "\(name):\(away):\(working ? Int(working5h) : 0)" }

  var summary: String {
    if working { return "Always · ≤\(Int(working5h))%" }
    return away ? "When away" : "Off"
  }
}

// My limits on lending, checked against my live utilization.
struct LendPolicy: Equatable {
  var away5h = 90.0
  var week = 60.0
  var awayAfterMinutes = 30
  var setting: String { "\(Int(away5h)):\(Int(week)):\(awayAfterMinutes)" }
}

// Whether I can borrow from someone right now, and why (not).
struct BorrowSource: Identifiable {
  var name: String
  var reason: String // away | working | off | unconnected | parked | unknown | full | weekFull
  var availablePoints: Double
  // Points left in each window, each in its own unit (never compared: a percent of a
  // week isn't a percent of a 5-hour window). Shown as two bars on the person's page.
  var left5h: Double?
  var leftWeek: Double?
  var id: String { name }
  var displayName: String { prettyName(name) }
  var available: Bool { reason == "away" || reason == "working" }

  var chip: String {
    switch reason {
    case "away", "working": return "\(Int(availablePoints))% left" // of their 5-hour window
    case "full", "weekFull": return "Full"
    case "parked": return "Paused"
    case "unconnected": return "Not set up"
    case "unknown": return "—"
    default: return "Off"
    }
  }

  var explanation: String {
    switch reason {
    case "away": return "Away"
    case "working": return "Working · lending to you"
    case "full": return "At their 5-hour limit"
    case "weekFull": return "At their weekly limit"
    case "parked": return "Hit their own limit"
    case "unconnected": return "Not set up yet"
    case "unknown": return "Usage unavailable"
    default: return "Not lending to you"
    }
  }
}

@MainActor
final class Store: ObservableObject {
  static let shared = Store()

  @Published var config: Config?
  @Published var setupInvite = ""
  // The invite last used to join, so going back during setup can offer it again.
  private var lastInvite = ""
  @Published var joinStatus: String?
  @Published var joinError: String?
  @Published var me: String?
  @Published var online = false
  @Published var lendingMembers: [LendingMember] = []
  @Published var borrowSources: [BorrowSource] = []
  @Published var borrowedWeekTotal = 0.0
  @Published var borrowedWeekByCaller: [String: Double] = [:]
  @Published var borrowed5h = 0.0
  @Published var borrowedByMeWeekTotal = 0.0
  @Published var borrowedByMeWeekByOwner: [String: Double] = [:]
  @Published var borrowedByMe5h = 0.0
  @Published var utilizationFiveHour: Double?
  @Published var utilizationSevenDay: Double?
  @Published var lentFiveHour: Double?  // the friends' part of each window (estimate)
  @Published var lentSevenDay: Double?
  @Published var policy = LendPolicy()
  @Published var away = false
  @Published var statusLine = "Not connected."
  @Published var busy = false
  @Published var lastApplied: String?
  @Published var subscriptionConnected = false
  @Published var routedThroughPool = false
  @Published var relayForced = false // config `privateBorrowing: false`: the readable relay, by hand
  @Published var poolSupportsPrivate = false // the pool has the MPC helper
  @Published var connectHint: String?
  @Published private var savedSettings: [String] = []

  @Published var saveError: String?
  @Published var canInvite = false

  private var refreshing = false
  private var refreshAgain = false
  // Consecutive 401s from the pool. One bad answer (a hiccup of the proxy in front
  // of the pool) must not wipe the local setup — only a streak means we were really
  // removed. Reset on every successful refresh.
  private var notAMemberStreak = 0
  private var pendingSave: Task<Void, Never>?

  var settingKey: [String] { lendingMembers.map(\.setting) + [policy.setting] }
  var hasChanges: Bool { settingKey != savedSettings }

  static let configURL = Profile.configURL

  // The app used to be called claudus; carry an existing install over once.
  static let legacyConfigURL = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".config/claudus-bar.json")
  static let legacyAgentLabel = "com.claudus.agent"

  init() {
    AppDelegate.store = self // so lembas:// links reach us even before the popover opens
    // Runs from launch, not from first opening the popover: membership changes and
    // updates are noticed even if nobody clicks the menu bar icon.
    Task { await self.autoRefresh() }
    if Profile.name == nil, !FileManager.default.fileExists(atPath: Self.configURL.path) {
      try? FileManager.default.moveItem(at: Self.legacyConfigURL, to: Self.configURL)
    }
    if let data = try? Data(contentsOf: Self.configURL),
       let cfg = try? JSONDecoder().decode(Config.self, from: data) {
      config = cfg
      relayForced = cfg.privateBorrowing == false
      if !AppLocation.isTranslocated { Task { try? await ensureAgentInstalled() } }
    }
  }

  private func number(_ value: Any?) -> Double {
    if let d = value as? Double { return d }
    if let i = value as? Int { return Double(i) }
    if let n = value as? NSNumber { return n.doubleValue }
    return 0
  }

  private func cleanURL(_ raw: String) -> String {
    var value = raw.trimmingCharacters(in: .whitespacesAndNewlines)
    while value.hasSuffix("/") { value.removeLast() }
    return value
  }

  private func saveConfig(_ cfg: Config) {
    try? FileManager.default.createDirectory(at: Self.configURL.deletingLastPathComponent(),
                                             withIntermediateDirectories: true)
    if let data = try? JSONEncoder().encode(cfg) {
      try? data.write(to: Self.configURL, options: .atomic)
      try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                             ofItemAtPath: Self.configURL.path)
    }
    config = cfg
  }

  // lembas://join?invite=<link> from an invite page. Any website can open such a link,
  // so it only fills in the code: the person still sees which pool it is and presses
  // Join. Ignored while already in a pool.
  func handleInviteLink(_ url: URL) {
    guard url.scheme == "lembas", url.host == "join",
          let invite = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems?
            .first(where: { $0.name == "invite" })?.value else { return }
    guard config == nil else {
      saveError = "You're already in a pool. Leave it first to join another."
      return
    }
    setupInvite = invite
    joinError = nil
    SetupWindow.show()
  }

  // The pool an invite (or pasted message) points at, to show before joining.
  var invitePoolHost: String? {
    let word = setupInvite.split(whereSeparator: \.isWhitespace).last { $0.contains("/") }.map(String.init)
    guard let word, let url = URL(string: word.hasPrefix("http") ? word : "https://" + word) else { return nil }
    return url.host
  }

  // Joining from an invite code like "https://mac.tail1234.ts.net/abcd-efgh-…" (or a
  // tailnet "100.1.2.3:8787/…"): swap the one-time code for this member's pool token,
  // then install the bundled agent and point Claude Code at it.
  func join() async {
    // Accept the whole copied invite message: the code is the word with a "/" in it.
    var raw = setupInvite.split(whereSeparator: \.isWhitespace).last { $0.contains("/") }.map(String.init)
      ?? setupInvite.trimmingCharacters(in: .whitespacesAndNewlines)
    if raw.hasPrefix("lembas://") { raw.removeFirst("lembas://".count) }
    if !raw.hasPrefix("http://") && !raw.hasPrefix("https://") { raw = "http://" + raw }
    guard let slash = raw.lastIndex(of: "/"), raw.distance(from: raw.startIndex, to: slash) > "https://".count,
          let redeemURL = URL(string: raw[..<slash] + "/pool/redeem") else {
      joinError = "That doesn't look like an invite code."
      return
    }
    let pool = String(raw[..<slash])
    let code = String(raw[raw.index(after: slash)...])
    busy = true
    joinError = nil
    defer { busy = false; joinStatus = nil }
    do {
      joinStatus = "Checking your invite…"
      var req = URLRequest(url: redeemURL)
      req.httpMethod = "POST"
      req.timeoutInterval = 10
      req.setValue("application/json", forHTTPHeaderField: "Content-Type")
      req.httpBody = try JSONSerialization.data(withJSONObject: ["code": code])
      let (data, resp) = try await URLSession.shared.data(for: req)
      let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] ?? [:]
      guard (resp as? HTTPURLResponse)?.statusCode == 200, let token = obj["token"] as? String else {
        let msg = (obj["error"] as? [String: Any])?["message"] as? String
        throw NSError(domain: "lembas", code: 0, userInfo: [NSLocalizedDescriptionKey: msg ?? "The pool rejected this invite."])
      }
      joinStatus = "Setting up lembas on this Mac…"
      saveConfig(Config(url: pool, token: token, agentPort: Profile.name == nil ? nil : Profile.agentPort))
      // (Re)starting the agent can take launchd several seconds; don't hold the screen
      // for it. Claude Code is pointed at the agent once it's up.
      Task {
        try? await ensureAgentInstalled(restart: true)
        setRouted(true)
      }
      lastInvite = setupInvite
      setupInvite = ""
      askOpenAtLogin = true // after connecting, the setup asks about opening at login
      await refresh()
    } catch let error as URLError {
      joinError = "Can't reach the pool. Check the code, or ask your friend whether their Mac is awake. (\(error.localizedDescription))"
    } catch {
      joinError = error.localizedDescription
    }
  }

  // GUI apps get a minimal PATH without homebrew — supply the usual suspects explicitly.
  private var shellEnvironment: [String: String] {
    let home = FileManager.default.homeDirectoryForCurrentUser.path
    return ["PATH": "/opt/homebrew/bin:/usr/local/bin:\(home)/.local/bin:/usr/bin:/bin:/usr/sbin:/sbin", "HOME": home]
  }

  // Runs a zsh snippet with positional arguments ($1, $2, …) and throws its last
  // stderr line if it fails.
  private func runShell(_ script: String, _ args: String...) async throws {
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/zsh")
    p.environment = shellEnvironment
    p.arguments = ["-c", script, "lembas"] + args
    let stderr = Pipe()
    p.standardOutput = FileHandle.nullDevice
    p.standardError = stderr
    let status: Int32 = try await withCheckedThrowingContinuation { cont in
      p.terminationHandler = { cont.resume(returning: $0.terminationStatus) }
      do { try p.run() } catch { cont.resume(throwing: error) }
    }
    guard status == 0 else {
      let text = String(decoding: stderr.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
      let line = text.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
        .last { !$0.isEmpty }
      throw NSError(domain: "lembas", code: Int(status),
                    userInfo: [NSLocalizedDescriptionKey: line.map { "Setup failed: \($0)" } ?? "Setup failed."])
    }
  }

  private func request(_ method: String, _ path: String, body: [String: Any]? = nil) async throws -> [String: Any] {
    guard let cfg = config else { throw URLError(.badURL) }
    guard let url = URL(string: cleanURL(cfg.url) + path) else { throw URLError(.badURL) }
    var req = URLRequest(url: url)
    req.timeoutInterval = 10
    req.httpMethod = method
    req.setValue("Bearer " + cfg.token, forHTTPHeaderField: "Authorization")
    if let body {
      req.httpBody = try JSONSerialization.data(withJSONObject: body)
      req.setValue("application/json", forHTTPHeaderField: "Content-Type")
    }
    let (data, resp) = try await URLSession.shared.data(for: req)
    guard let http = resp as? HTTPURLResponse else { throw URLError(.badServerResponse) }
    guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
      throw URLError(.cannotParseResponse)
    }
    if http.statusCode == 401 { throw NotAMember() } // our pool token is no longer valid
    if http.statusCode >= 400 {
      let msg = ((obj["error"] as? [String: Any])?["message"] as? String) ?? "HTTP \(http.statusCode)"
      throw NSError(domain: "lembas", code: http.statusCode,
                    userInfo: [NSLocalizedDescriptionKey: msg])
    }
    return obj
  }

  // Asks the pool for everything the popover shows. A request made while one is in
  // flight (e.g. right after joining) runs once that one finishes — never dropped,
  // or the screen could wait for the next background refresh.
  func refresh() async {
    guard config != nil else { return }
    if refreshing {
      refreshAgain = true
      return
    }
    refreshing = true
    defer { refreshing = false }
    repeat {
      refreshAgain = false
      await refreshOnce()
    } while refreshAgain && config != nil
  }

  private func refreshOnce() async {
    guard config != nil else { return }
    reloadRoute()
    do {
      let obj = try await request("GET", "/pool")
      me = obj["you"] as? String
      canInvite = obj["canInvite"] as? Bool ?? false
      poolSupportsPrivate = obj["privateBorrowing"] as? Bool ?? false
      online = true
      loaded = true
      notAMemberStreak = 0
      statusLine = "Connected."

      guard let me, let user = obj[me] as? [String: Any] else {
        online = false
        statusLine = "Signed in, but this token is not in the pool."
        return
      }

      subscriptionConnected = user["subscriptionConnected"] as? Bool ?? false
      inviteReturnable = user["inviteReturnable"] as? Bool ?? false
      if subscriptionConnected { connectHint = nil }

      if let week = user["borrowedFromMeThisWeekUsd"] as? [String: Any] {
        borrowedWeekTotal = number(week["total"])
        if let by = week["byCaller"] as? [String: Any] {
          borrowedWeekByCaller = by.mapValues { number($0) }
        } else {
          borrowedWeekByCaller = [:]
        }
      } else {
        borrowedWeekTotal = 0
        borrowedWeekByCaller = [:]
      }
      borrowed5h = number(user["borrowedFromMeLast5hUsd"])
      if let week = user["borrowedByMeThisWeekUsd"] as? [String: Any] {
        borrowedByMeWeekTotal = number(week["total"])
        borrowedByMeWeekByOwner = (week["byOwner"] as? [String: Any])?.mapValues { number($0) } ?? [:]
      } else {
        borrowedByMeWeekTotal = 0
        borrowedByMeWeekByOwner = [:]
      }
      borrowedByMe5h = number(user["borrowedByMeLast5hUsd"])
      away = (user["presence"] as? [String: Any])?["away"] as? Bool ?? false

      if let util = user["utilization"] as? [String: Any] {
        utilizationFiveHour = number(util["fiveHour"])
        utilizationSevenDay = number(util["sevenDay"])
        lentFiveHour = number(util["lentFiveHour"])
        lentSevenDay = number(util["lentSevenDay"])
      } else {
        utilizationFiveHour = nil
        utilizationSevenDay = nil
      }

      var fresh: [LendingMember] = []
      if let lending = user["lending"] as? [String: [String: Any]] {
        fresh = lending.map { name, row in
          let working5h = number(row["working5h"])
          return LendingMember(name: name, away: row["away"] as? Bool ?? false,
                               working: working5h > 0, working5h: working5h > 0 ? working5h : 40)
        }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
      }
      var freshPolicy = LendPolicy()
      if let p = user["policy"] as? [String: Any] {
        freshPolicy = LendPolicy(away5h: number(p["away5h"]), week: number(p["week"]),
                                 awayAfterMinutes: Int(number(p["awayAfterMinutes"])))
      }
      // Keep unsaved edits (a save is pending); otherwise take the server's view.
      if !hasChanges || Set(fresh.map(\.name)) != Set(lendingMembers.map(\.name)) {
        lendingMembers = fresh
        policy = freshPolicy
      }
      savedSettings = fresh.map(\.setting) + [freshPolicy.setting]

      if let borrowing = user["borrowingFrom"] as? [String: [String: Any]] {
        borrowSources = borrowing.map { name, row in
          BorrowSource(name: name, reason: row["reason"] as? String ?? "off",
                       availablePoints: number(row["availablePoints"]),
                       left5h: (row["left5h"] as? NSNumber)?.doubleValue,
                       leftWeek: (row["leftWeek"] as? NSNumber)?.doubleValue)
        }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
      } else {
        borrowSources = []
      }
    } catch is NotAMember {
      // Removed by an admin, or left from another copy: tidy up like leaving does —
      // but only after several 401s in a row, never on one. A single bad answer (say,
      // from a flaky connection to the pool) used to delete the config and the agent,
      // which took Claude Code's endpoint down with it.
      notAMemberStreak += 1
      if notAMemberStreak >= 3 {
        await forgetMembership()
        joinError = "You're no longer in this pool."
      } else {
        online = false
        statusLine = "The pool rejected this token — rechecking (\(notAMemberStreak)/3)…"
      }
    } catch {
      online = false
      loaded = true // show the main screen with the error rather than spin forever
      statusLine = "Can't reach the pool right now. Borrowing is paused — Claude Code still works normally."
    }
  }

  // ----- Claude Code routing: direct, or through the pool -----

  static let claudeSettings = Profile.claudeSettings
  static let localAgentURL = "http://127.0.0.1:\(Profile.agentPort)"

  func reloadRoute() {
    guard let data = try? Data(contentsOf: Self.claudeSettings),
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let env = obj["env"] as? [String: Any] else {
      routedThroughPool = false
      return
    }
    routedThroughPool = (env["ANTHROPIC_BASE_URL"] as? String) == Self.localAgentURL
  }

  func setRouted(_ on: Bool) {
    var obj: [String: Any] = [:]
    if let data = try? Data(contentsOf: Self.claudeSettings),
       let parsed = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
      obj = parsed
    }
    var env = obj["env"] as? [String: Any] ?? [:]
    if on {
      env["ANTHROPIC_BASE_URL"] = Self.localAgentURL
      env.removeValue(forKey: "ANTHROPIC_AUTH_TOKEN") // keep the native claude.ai login and UI
    } else {
      env.removeValue(forKey: "ANTHROPIC_BASE_URL")
      env.removeValue(forKey: "ANTHROPIC_AUTH_TOKEN")
    }
    if env.isEmpty { obj.removeValue(forKey: "env") } else { obj["env"] = env }
    if let data = try? JSONSerialization.data(withJSONObject: obj, options: [.prettyPrinted, .sortedKeys]) {
      try? FileManager.default.createDirectory(at: Self.claudeSettings.deletingLastPathComponent(),
                                               withIntermediateDirectories: true)
      try? data.write(to: Self.claudeSettings, options: .atomic)
      try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                             ofItemAtPath: Self.claudeSettings.path)
    }
    routedThroughPool = on
  }

  // ----- subscription connect: runs the pool's login helper (browser flow) -----

  // ----- first-run setup after joining: connect the subscription, then open at login -----

  // Set once the pool has answered, so setup pages don't flash before we know.
  @Published var loaded = false
  // Remembered per profile until answered, so a relaunch mid-setup comes back to it.
  // Joined but not set up yet: "Use a different invite" is safe and returns the invite.
  @Published var inviteReturnable = false
  @Published var askOpenAtLogin = UserDefaults.standard.bool(forKey: "askOpenAtLogin\(Profile.name.map { "." + $0 } ?? "")") {
    didSet { UserDefaults.standard.set(askOpenAtLogin, forKey: "askOpenAtLogin\(Profile.name.map { "." + $0 } ?? "")") }
  }
  @Published var opensAtLogin = SMAppService.mainApp.status == .enabled

  // The setup checklist shows after joining until Done, and whenever the pool says our
  // subscription isn't connected (connecting is required to take part).
  var needsSetup: Bool { online && (!subscriptionConnected || askOpenAtLogin) }

  // Which screen the popover shows. Every screen has the same size, so switching
  // never resizes the menu bar window.
  enum Screen { case move, join, loading, setup, main }
  var screen: Screen {
    if AppLocation.isTranslocated { return .move }
    if config == nil { return .join }
    if !loaded { return .loading }
    return needsSetup ? .setup : .main
  }

  func setOpenAtLogin(_ on: Bool) {
    do {
      if on { try SMAppService.mainApp.register() } else { try SMAppService.mainApp.unregister() }
    } catch {
      saveError = "Couldn't change Open at Login: \(error.localizedDescription)"
    }
    opensAtLogin = SMAppService.mainApp.status == .enabled
  }

  private var connectTask: Task<Void, Never>?
  private var connectAttempt = 0

  // Starts a browser login. Calling it again while one is waiting (Retry — e.g. the tab
  // was closed) cancels that attempt first and opens a fresh one.
  func runConnect() {
    guard let cfg = config else { return }
    let previous = connectTask
    previous?.cancel()
    connectAttempt += 1
    let attempt = connectAttempt
    connectHint = "Waiting for your browser…"
    PopoverPin.pinned = true // keep the checklist up next to the browser
    connectTask = Task {
      await previous?.value // let it release the login port before we reuse it
      defer { if attempt == connectAttempt { PopoverPin.pinned = false } }
      do {
        try await SubscriptionLogin.run(pool: cleanURL(cfg.url), poolToken: cfg.token)
        connectHint = nil
        await refresh()
      } catch is CancellationError {
        return // replaced by a newer attempt
      } catch {
        connectHint = "Couldn't connect: \(error.localizedDescription)"
      }
      NSApp.activate(ignoringOtherApps: true) // bring the ticked-off checklist forward
    }
  }

  // ----- the bundled agent (Contents/MacOS/lembas-agent), run by launchd -----

  static let agentLabel = Profile.agentLabel
  static let agentPlist = Profile.agentPlist
  private var bundledAgent: String { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/lembas-agent").path }
  // The MPC-TLS helper for private borrowing, built by ./build.sh; a build without Rust has none.
  private var bundledHelper: String { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/lembas-mpc").path }
  // The agent runs from its own copy outside the app, so deleting lembas.app can't take
  // Claude Code down with it: the agent notices, retires safely, and removes this copy.
  private static let installedAgent = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/Application Support/lembas/\(Profile.agentLabel)/lembas-agent")

  // launchd keeps the agent running (and restarts it) even when this app is closed.
  // Refreshes the agent copy after updates and rewrites the job whenever it differs,
  // e.g. an older install that ran the agent from inside the app bundle.
  func ensureAgentInstalled(restart: Bool = false) async throws {
    guard FileManager.default.isExecutableFile(atPath: bundledAgent) else { return }
    let legacyPlist = Self.agentPlist.deletingLastPathComponent().appendingPathComponent("\(Self.legacyAgentLabel).plist")
    if Profile.name == nil, FileManager.default.fileExists(atPath: legacyPlist.path) {
      // Free port 8788 from the old claudus agent before ours takes over.
      try? await runShell("launchctl bootout gui/$(id -u)/$1 2>/dev/null; sleep 1", Self.legacyAgentLabel)
      try? FileManager.default.removeItem(at: legacyPlist)
    }

    // Copy (as a new file, never overwriting the running binary in place) when it changed.
    let installed = Self.installedAgent
    var agentChanged = false
    if FileManager.default.contents(atPath: installed.path) != FileManager.default.contents(atPath: bundledAgent) {
      try FileManager.default.createDirectory(at: installed.deletingLastPathComponent(), withIntermediateDirectories: true)
      try? FileManager.default.removeItem(at: installed)
      try FileManager.default.copyItem(atPath: bundledAgent, toPath: installed.path)
      // A downloaded app is quarantined; its copy would inherit that without the "Open
      // Anyway" approval the app got, and macOS could refuse to start it in the background.
      removexattr(installed.path, "com.apple.quarantine", 0)
      agentChanged = true
    }
    // The helper sits next to the agent, where the agent looks for it by default.
    let installedHelper = installed.deletingLastPathComponent().appendingPathComponent("lembas-mpc")
    if FileManager.default.isExecutableFile(atPath: bundledHelper),
       FileManager.default.contents(atPath: installedHelper.path) != FileManager.default.contents(atPath: bundledHelper) {
      try? FileManager.default.removeItem(at: installedHelper)
      try FileManager.default.copyItem(atPath: bundledHelper, toPath: installedHelper.path)
      removexattr(installedHelper.path, "com.apple.quarantine", 0)
    }

    let plist: [String: Any] = [
      "Label": Self.agentLabel,
      "ProgramArguments": [installed.path],
      "EnvironmentVariables": [
        "LEMBAS_AGENT_CONFIG": Self.configURL.path,
        "LEMBAS_AGENT_PORT": String(Profile.agentPort),
        "LEMBAS_APP_PATH": Bundle.main.bundlePath,
        "LEMBAS_CLAUDE_SETTINGS": Self.claudeSettings.path,
        "LEMBAS_AGENT_LABEL": Self.agentLabel,
        "LEMBAS_AGENT_PLIST": Self.agentPlist.path,
        "LEMBAS_MPC_HELPER": installedHelper.path,
      ],
      "RunAtLoad": true,
      "KeepAlive": true,
      "ThrottleInterval": 2, // restart promptly (launchd's default waits 10 s)
      "StandardOutPath": Profile.agentLog,
      "StandardErrorPath": Profile.agentLog,
    ]
    if NSDictionary(contentsOf: Self.agentPlist) == NSDictionary(dictionary: plist) {
      if restart || agentChanged { try await runShell("launchctl kickstart -k gui/$(id -u)/$1", Self.agentLabel) }
      return
    }
    let firstInstall = !FileManager.default.fileExists(atPath: Self.agentPlist.path)
    try FileManager.default.createDirectory(at: Self.agentPlist.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: Self.agentPlist)
    // The pause lets the old agent release its port before the new one starts.
    try await runShell("launchctl bootout gui/$(id -u)/$1 2>/dev/null && sleep 1; launchctl bootstrap gui/$(id -u) \"$2\"",
                       Self.agentLabel, Self.agentPlist.path)
    if firstInstall { setRouted(true) } // fresh Terminal install: point Claude Code at the agent
  }

  // ----- updates, from GitHub releases built by CI from the public source -----
  // Never from the pool: whoever runs a pool must not be able to ship code to members.
  // LEMBAS_UPDATES points elsewhere for testing (a folder served like a release).

  static let releases = ProcessInfo.processInfo.environment["LEMBAS_UPDATES"]
    ?? "https://github.com/bodino/lembas/releases"

  @Published var update: AvailableUpdate?
  @Published var updateStatus: String?
  private var lastUpdateCheck = Date.distantPast

  static let currentBuild = Int(Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "") ?? 0
  static let currentVersion = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? ""

  func checkForUpdate(force: Bool = false) async {
    // Polled about once a minute (and when the popover opens); version.json is tiny and
    // served from GitHub's download CDN, not its rate-limited API.
    guard force || Date().timeIntervalSince(lastUpdateCheck) > 55 else { return }
    lastUpdateCheck = Date()
    guard let latest = await latestBuild() else { return }
    update = latest.build > Self.currentBuild ? latest : nil
    if update != nil {
      // Drop an earlier "up to date" so the row offers the update (keep install progress).
      if updateStatus == "lembas is up to date." { updateStatus = nil }
    } else if force {
      updateStatus = "lembas is up to date."
      try? await Task.sleep(nanoseconds: 4_000_000_000)
      if updateStatus == "lembas is up to date." { updateStatus = nil }
    }
  }

  // The latest release's version.json.
  private func latestBuild() async -> AvailableUpdate? {
    guard let url = URL(string: Self.releases + "/latest/download/version.json"),
          let (data, response) = try? await URLSession.shared.data(from: url),
          (response as? HTTPURLResponse)?.statusCode == 200,
          let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
          let build = (obj["build"] as? NSNumber)?.intValue, let sha = obj["sha256"] as? String else { return nil }
    return AvailableUpdate(version: obj["version"] as? String ?? "", build: build, sha256: sha)
  }

  // Downloads that release's lembas.zip (by its tag, so a newer release appearing
  // mid-download can't mix them up) and checks it against version.json.
  private func downloadVerifiedBuild() async throws -> Data {
    guard let latest = await latestBuild() else { throw URLError(.cannotConnectToHost) }
    guard let url = URL(string: Self.releases + "/download/v\(latest.version)/lembas.zip") else { throw URLError(.badURL) }
    let (file, response) = try await URLSession.shared.download(from: url)
    guard (response as? HTTPURLResponse)?.statusCode == 200 else { throw URLError(.fileDoesNotExist) }
    let data = try Data(contentsOf: file)
    guard SHA256.hash(data: data).map({ String(format: "%02x", $0) }).joined() == latest.sha256 else {
      throw LoginError("the download didn't match the published checksum")
    }
    return data
  }

  // Downloads the new app, checks it, then swaps it in after quitting: a small script
  // waits for this process to exit, replaces the bundle, restarts the agent on the new
  // binary and relaunches.
  func installUpdate() async {
    guard update != nil else { return }
    updateStatus = "Downloading…"
    do {
      let data = try await downloadVerifiedBuild()
      let work = FileManager.default.temporaryDirectory.appendingPathComponent("lembas-update-\(UUID().uuidString)")
      try FileManager.default.createDirectory(at: work, withIntermediateDirectories: true)
      try data.write(to: work.appendingPathComponent("lembas.zip"))
      try await runShell("cd \"$1\" && /usr/bin/ditto -x -k lembas.zip .", work.path)
      let fresh = work.appendingPathComponent("lembas.app")
      guard Bundle(url: fresh)?.bundleIdentifier == Bundle.main.bundleIdentifier else {
        throw LoginError("the download isn't a lembas app")
      }
      let script = """
        while kill -0 "$1" 2>/dev/null; do sleep 0.2; done
        rm -rf "$2" && mv "$3" "$2" || exit 1
        launchctl kickstart -k "gui/$(id -u)/$4" 2>/dev/null
        # -n: start a fresh copy even if another profile of lembas is running from this bundle.
        if [ -n "$6" ]; then open -n "$2" --env "LEMBAS_PROFILE=$6"; else open -n "$2"; fi
        rm -rf "$5"
        """
      let swap = Process()
      swap.executableURL = URL(fileURLWithPath: "/bin/sh")
      swap.arguments = ["-c", script, "lembas-update", String(ProcessInfo.processInfo.processIdentifier),
                        Bundle.main.bundlePath, fresh.path, Self.agentLabel, work.path, Profile.name ?? ""]
      try swap.run()
      updateStatus = "Restarting…"
      try? await Task.sleep(nanoseconds: 600_000_000) // let "Restarting…" show
      NSApp.terminate(nil)
    } catch {
      updateStatus = "Update failed: \(error.localizedDescription)"
    }
  }

  // Leaves the pool (which deletes our subscription access there), then undoes what
  // joining set up on this Mac: the agent, Claude Code's base URL and the config.
  func leavePool() async -> Bool {
    busy = true
    defer { busy = false }
    do {
      _ = try await request("POST", "/pool/leave")
    } catch is NotAMember {
      // Already out of the pool; just clean up this Mac.
    } catch {
      saveError = "Couldn't leave: \(error.localizedDescription)"
      return false
    }
    await forgetMembership()
    return true
  }

  // Back from setup: leave (the pool makes the invite valid again since nothing was
  // connected) and show the join screen with that invite filled in.
  func goBackToJoin() async {
    let invite = lastInvite
    if await leavePool() { setupInvite = invite }
  }

  // Undoes what joining set up on this Mac: the agent, Claude Code's base URL and the
  // config. The app goes back to the join screen.
  private func forgetMembership() async {
    setRouted(false) // new Claude Code sessions go straight to Anthropic
    // Don't stop the agent: sessions already running still point at it. Without a config
    // it serves them direct-only and removes itself once they're gone.
    try? FileManager.default.removeItem(at: Self.configURL)
    askOpenAtLogin = false
    saveError = nil
    me = nil
    loaded = false
    online = false
    lendingMembers = []
    borrowSources = []
    config = nil // back to the join screen
  }

  func removeMember(_ name: String) async {
    do {
      _ = try await request("DELETE", "/pool/members/\(name)")
      saveError = nil
      await refresh()
    } catch {
      saveError = "Couldn't remove \(prettyName(name)): \(error.localizedDescription)"
    }
  }

  func apply() async {
    busy = true
    defer { busy = false }
    var lendTo: [String: Any] = [:]
    for member in lendingMembers {
      lendTo[member.name] = ["away": member.away, "working5h": member.working ? Int(member.working5h) : 0]
    }
    let policyBody: [String: Any] = ["away5h": Int(policy.away5h), "week": Int(policy.week),
                                     "awayAfterMinutes": policy.awayAfterMinutes]
    do {
      _ = try await request("PUT", "/pool/share", body: ["lendTo": lendTo, "policy": policyBody])
      lastApplied = Date.now.formatted(date: .omitted, time: .shortened)
      saveError = nil
      await refresh()
    } catch {
      saveError = "Couldn't save: \(error.localizedDescription)"
    }
  }

  // "I'm done for today" (lend now) / "I'm back".
  func setAway(_ value: Bool) async {
    away = value
    do {
      _ = try await request("PUT", "/pool/presence", body: ["away": value])
      await refresh()
    } catch {
      saveError = "Couldn't update: \(error.localizedDescription)"
    }
  }

  // Dial edits save themselves once the user stops dragging for a moment.
  func scheduleSave() {
    pendingSave?.cancel()
    guard hasChanges else { return }
    pendingSave = Task {
      try? await Task.sleep(nanoseconds: 700_000_000)
      guard !Task.isCancelled else { return }
      await apply()
    }
  }

  // Admin only: adds someone to the pool and returns the join one-liner to send them.
  func invite(_ name: String) async throws -> String {
    let obj = try await request("POST", "/pool/invite", body: ["name": name])
    await refresh()
    return obj["invite"] as? String ?? ""
  }

  // Keeps the numbers current while the app runs; also retries an unreachable pool.
  func autoRefresh() async {
    while !Task.isCancelled {
      await refresh()
      await checkForUpdate()
      try? await Task.sleep(nanoseconds: 30_000_000_000)
    }
  }
}

// First run: join a pool with an invite code. Same layout as the Invite page.
struct SetupView: View {
  @EnvironmentObject var store: Store
  @FocusState private var focused: Bool

  private var canJoin: Bool { !store.setupInvite.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !store.busy }

  var body: some View {
    VStack(spacing: 0) {
      PopoverHeader()
      Spacer(minLength: 12)
      Hero(icon: "envelope.open.fill", title: "Join a pool",
           subtitle: "Paste the invite a friend sent you.")

      TextField("Invite code", text: $store.setupInvite)
        .textFieldStyle(.plain)
        .font(Typography.body)
        .padding(.horizontal, Spacing.card)
        .padding(.vertical, Spacing.card)
        .background(InputBackground())
        .focused($focused)
        .disabled(store.busy)
        .onSubmit { if canJoin { Task { await store.join() } } }
        .padding(.top, Spacing.section)

      MessageSlot {
        if let status = store.joinStatus {
          HStack(spacing: 6) {
            ProgressView().controlSize(.small)
            Text(status).font(Typography.caption).foregroundStyle(.secondary)
          }
          .transition(.opacity)
        } else if let error = store.joinError {
          Text(error)
            .font(Typography.caption)
            .foregroundStyle(.orange)
            .lineLimit(2)
            .transition(.opacity)
        } else if let host = store.invitePoolHost {
          Label("Pool at \(host)", systemImage: "network")
            .font(Typography.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
            .transition(.opacity)
        }
      }
      .padding(.top, Spacing.header)
      .animation(.easeInOut(duration: 0.15), value: store.invitePoolHost)
      .animation(.easeInOut(duration: 0.15), value: store.joinStatus)
      .animation(.easeInOut(duration: 0.15), value: store.joinError)

      Button { Task { await store.join() } } label: {
        Text(store.busy ? "Joining…" : "Join").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .tint(accent)
      .keyboardShortcut(.defaultAction)
      .disabled(!canJoin)
      .padding(.top, 10)
      Spacer(minLength: 12)
    }
    .padding(.horizontal, Spacing.edge)
    .padding(.vertical, Spacing.page)
    .onAppear { focused = true }
  }
}

// Layout follows the system menu bar popovers (Wi‑Fi, Bluetooth): 14pt content inset,
// inset separators, rows that highlight on hover. Neutral surfaces and system text
// colors throughout; the system accent color for controls. Lend (↗) vs borrow (↙) is told
// apart by the arrow, not by color.
private let inset: CGFloat = 14

// The app's whole spacing scale, used everywhere instead of one-off numbers.
enum Spacing {
  static let edge: CGFloat = inset    // popover edges, on every screen and page
  static let page: CGFloat = 10       // top and bottom margin of every page
  static let section: CGFloat = 16    // between sections (a header plus its content)
  static let header: CGFloat = 6      // section header to its content
  static let card: CGFloat = 10       // padding inside cards, and between stacked cards
}

// The app's whole type scale. Icons size their glyphs separately.
enum Typography {
  static let title = Font.system(size: 13, weight: .semibold)  // names, titles, Working/Away
  static let body = Font.system(size: 12)                      // row labels, controls, values
  static let caption = Font.system(size: 11)                   // secondary lines, tags, slider labels
  static let figure = Font.system(size: 20, weight: .semibold, design: .rounded) // the two weekly totals
}
private let accent = Color.accentColor // follows System Settings › Appearance
private let friendsColor = Color.orange // friends' share of your usage

// The menu bar window is see-through glass, so whatever is behind it (often a light
// wallpaper) washes the content out. A solid window background keeps text and
// controls at full contrast in light and dark mode.
// In dark mode a touch lighter than the system's #1e1e1e window background.
private let popoverBackground = Color(nsColor: NSColor(name: nil) { appearance in
  appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    ? NSColor(srgbRed: 0x24 / 255, green: 0x24 / 255, blue: 0x24 / 255, alpha: 1)
    : .windowBackgroundColor
})

struct Avatar: View {
  let name: String
  var size: CGFloat = 28
  var body: some View {
    ZStack {
      Circle().fill(accent)
      Text(String(prettyName(name).prefix(1)))
        .font(.system(size: size * 0.46, weight: .semibold, design: .rounded))
        .foregroundStyle(.white)
    }
    .frame(width: size, height: size)
  }
}

struct AppBadge: View {
  private static let image = LembasLogo.tile(size: 28)
  var body: some View {
    Image(nsImage: Self.image)
      .frame(width: 28, height: 28)
      .accessibilityLabel("lembas")
  }
}

struct Chip: View {
  let icon: String
  let text: String
  let active: Bool
  var body: some View {
    HStack(spacing: 3) {
      Image(systemName: icon).font(.system(size: 8, weight: .bold)).foregroundStyle(active ? accent : Color.secondary)
      Text(text).font(Typography.caption).monospacedDigit()
    }
    .padding(.horizontal, 6)
    .padding(.vertical, 2)
    .foregroundStyle(active ? Color.primary : Color.secondary)
    .background(Capsule().fill(active ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.quinary)))
  }
}

struct WeekTile: View {
  let title: String
  let icon: String
  let value: Double
  var body: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack(spacing: 5) {
        Image(systemName: icon)
          .font(.system(size: 8, weight: .bold))
          .foregroundStyle(.white)
          .frame(width: 16, height: 16)
          .background(Circle().fill(accent))
        Text(title).font(Typography.caption).foregroundStyle(.secondary)
      }
      Text(dollars(value))
        .font(Typography.figure)
        .monospacedDigit()
    }
    .padding(Spacing.card)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(card)
  }
}

private var card: some View {
  RoundedRectangle(cornerRadius: 10, style: .continuous)
    .fill(.quinary)
}

struct Notice: View {
  let text: String
  var body: some View {
    Label(text, systemImage: "exclamationmark.triangle.fill")
      .font(Typography.caption)
      .foregroundStyle(.orange)
      .fixedSize(horizontal: false, vertical: true)
  }
}

struct SectionHeader: View {
  let title: String
  var body: some View {
    Text(title)
      .font(Typography.title)
      .foregroundStyle(.secondary)
      .padding(.horizontal, Spacing.edge)
      .padding(.bottom, Spacing.header)
  }
}

struct MenuSeparator: View {
  var body: some View {
    Divider().padding(.horizontal, inset).padding(.vertical, 6)
  }
}

// A row that highlights on hover, inset like native menu items.
struct HoverRow<Content: View>: View {
  var action: () -> Void
  @ViewBuilder var content: Content
  @State private var hovering = false
  var body: some View {
    Button(action: action) {
      content
        .padding(.horizontal, inset - 5)
        .padding(.vertical, 5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .contentShape(Rectangle())
        .background(
          RoundedRectangle(cornerRadius: 6, style: .continuous)
            .fill(hovering ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.clear))
        )
    }
    .buttonStyle(.plain)
    .padding(.horizontal, 5)
    .onHover { hovering = $0 }
  }
}

struct PercentSlider: View {
  let label: String
  @Binding var value: Double
  var labelWidth: CGFloat = 20
  var body: some View {
    HStack(spacing: 8) {
      Text(label)
        .font(Typography.caption)
        .foregroundStyle(.secondary)
        .frame(width: labelWidth, alignment: .leading)
      // Snaps to 5% without `step:`, which would draw a tick mark for every stop.
      Slider(value: Binding(get: { value }, set: { value = ($0 / 5).rounded() * 5 }), in: 5...100)
        .controlSize(.mini)
        .tint(accent)
      Text("\(Int(value))%")
        .font(Typography.caption)
        .monospacedDigit()
        .frame(width: 34, alignment: .trailing)
    }
  }
}

// Centered icon, title and one line: the top of the invite and join pages.
struct Hero: View {
  let icon: String
  let title: String
  let subtitle: String
  var body: some View {
    VStack(spacing: 6) {
      Image(systemName: icon)
        .font(.system(size: 20, weight: .semibold))
        .foregroundStyle(.white)
        .frame(width: 48, height: 48)
        .background(Circle().fill(accent))
        .padding(.bottom, 6)
      Text(title).font(Typography.title).lineLimit(1)
      Text(subtitle)
        .font(Typography.body)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .lineLimit(2)
        .frame(height: 32, alignment: .top) // always two lines' room: wrapping never moves anything
    }
    .frame(maxWidth: .infinity)
  }
}

// A line under a field for hints, progress and errors. It always takes the same space
// (two caption lines), so text appearing or changing never moves the layout.
struct MessageSlot<Content: View>: View {
  var alignment: Alignment = .topLeading
  @ViewBuilder var content: Content
  var body: some View {
    ZStack(alignment: alignment) { content }
      .frame(maxWidth: .infinity, minHeight: 30, maxHeight: 30, alignment: alignment)
  }
}

// A solid input surface that stays readable on the popover.
struct InputBackground: View {
  var body: some View {
    RoundedRectangle(cornerRadius: 8, style: .continuous)
      .fill(Color(nsColor: .textBackgroundColor))
      .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.quaternary))
  }
}

// Read-only counterpart of PercentSlider (same label, track and value columns).
struct UsageBar: View {
  let label: String
  let percent: Double?
  var lent: Double? = nil // the part of `percent` friends used, drawn in its own color
  var labelWidth: CGFloat = 34
  var body: some View {
    HStack(spacing: 8) {
      Text(label)
        .font(Typography.caption)
        .foregroundStyle(.secondary)
        .frame(width: labelWidth, alignment: .leading)
      GeometryReader { geo in
        let total = min(max(percent ?? 0, 0), 100)
        let friends = min(max(lent ?? 0, 0), total)
        ZStack(alignment: .leading) {
          Capsule().fill(.quaternary)
          HStack(spacing: 0) {
            Rectangle().fill(accent).frame(width: geo.size.width * (total - friends) / 100)
            Rectangle().fill(friendsColor).frame(width: geo.size.width * friends / 100)
          }
          .clipShape(Capsule())
        }
      }
      .frame(height: 4)
      Text(percent.map { "\(Int($0))%" } ?? "—")
        .font(Typography.caption)
        .monospacedDigit()
        .frame(width: 34, alignment: .trailing)
    }
    .animation(.easeInOut(duration: 0.3), value: percent)
  }
}

struct SwitchRow: View {
  let title: String
  @Binding var isOn: Bool
  var body: some View {
    HStack {
      Text(title).font(Typography.body)
      Spacer()
      Toggle(title, isOn: $isOn)
        .labelsHidden()
        .toggleStyle(.switch)
        .controlSize(.mini)
        .tint(accent)
    }
  }
}

struct BackHeader: View {
  let title: String
  let back: () -> Void
  var body: some View {
    HStack(spacing: 8) {
      Button(action: back) {
        Image(systemName: "chevron.left")
          .font(.system(size: 12, weight: .semibold))
          .frame(width: 22, height: 22)
          .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
      .keyboardShortcut(.cancelAction)
      Text(title).font(Typography.title)
      Spacer()
    }
  }
}

struct PersonRow: View {
  let member: LendingMember
  let source: BorrowSource?
  let open: () -> Void
  var body: some View {
    HoverRow(action: open) {
      HStack(spacing: 10) {
        Avatar(name: member.name)
        VStack(alignment: .leading, spacing: 3) {
          Text(member.displayName).font(Typography.title)
          HStack(spacing: 4) {
            Chip(icon: "arrow.up.right", text: member.summary, active: member.away || member.working)
            Chip(icon: "arrow.down.left", text: source?.chip ?? "Off", active: source?.available == true)
          }
        }
        Spacer(minLength: 4)
        Image(systemName: "chevron.right")
          .font(.system(size: 10, weight: .semibold))
          .foregroundStyle(.tertiary)
      }
    }
  }
}

// Drill-in page for one person, drawn over the main page so the window keeps its size.
struct PersonDetail: View {
  @Binding var member: LendingMember
  let source: BorrowSource?
  let lentThisWeek: Double
  let borrowedThisWeek: Double
  var remove: (() -> Void)? // admins only
  let back: () -> Void
  @State private var confirmingRemove = false

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      HStack(spacing: 8) {
        Button(action: back) {
          Image(systemName: "chevron.left")
            .font(.system(size: 12, weight: .semibold))
            .frame(width: 22, height: 22)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .keyboardShortcut(.cancelAction)
        Avatar(name: member.name, size: 24)
        Text(member.displayName).font(Typography.title)
        Spacer()
      }

      VStack(alignment: .leading, spacing: 8) {
        HStack {
          sectionLabel("You lend \(member.displayName)", "arrow.up.right")
          Spacer()
        }
        SwitchRow(title: "When I'm away", isOn: $member.away)
        SwitchRow(title: "While I'm working", isOn: $member.working)
        if member.working {
          // "5h" like the Lending limits page: lend until my 5-hour window reaches this.
          PercentSlider(label: "5h", value: $member.working5h, labelWidth: 34)
        }
      }
      .padding(Spacing.card)
      .background(card)

      VStack(alignment: .leading, spacing: 8) {
        sectionLabel("\(member.displayName) lends you", "arrow.down.left")
        Text(source?.explanation ?? "Not lending to you")
          .font(Typography.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
        // What's left to borrow in each window: borrowing stops at whichever runs out first.
        if let source, source.available {
          UsageBar(label: "5h left", percent: source.left5h, labelWidth: 56)
        }
      }
      .padding(Spacing.card)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(card)

      HStack(spacing: 10) {
        Text("This week").foregroundStyle(.secondary)
        Spacer()
        Label(dollars(lentThisWeek), systemImage: "arrow.up.right")
        Label(dollars(borrowedThisWeek), systemImage: "arrow.down.left")
      }
      .font(Typography.caption.monospacedDigit())
      .padding(.horizontal, 2)

      if let remove {
        if confirmingRemove {
          // Same footprint as the button it replaces: the popover can't grow.
          HStack(spacing: 8) {
            Button { confirmingRemove = false } label: {
              Text("Cancel").frame(maxWidth: .infinity)
            }
            Button(role: .destructive, action: remove) {
              Text("Remove \(member.displayName)").frame(maxWidth: .infinity)
            }
            .buttonStyle(.borderedProminent)
            .tint(.red)
            .help("Their pool access stops right away")
          }
          .controlSize(.large)
        } else {
          Button { confirmingRemove = true } label: {
            Label("Remove from Pool", systemImage: "person.badge.minus")
              .font(Typography.title)
              .foregroundStyle(.red)
              .frame(maxWidth: .infinity)
              .padding(.vertical, 7)
              .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(.quaternary))
              .contentShape(Rectangle())
          }
          .buttonStyle(.plain)
        }
      }
    }
    .padding(.horizontal, inset)
  }

  private func sectionLabel(_ title: String, _ icon: String) -> some View {
    HStack(spacing: 5) {
      Image(systemName: icon).font(.system(size: 10, weight: .bold)).foregroundStyle(accent)
      Text(title).font(Typography.title)
    }
  }
}

struct InviteView: View {
  @EnvironmentObject var store: Store
  let back: () -> Void
  @State private var name = ""
  @State private var code: String?
  @State private var error: String?
  @State private var working = false
  @State private var copied = false
  @FocusState private var nameFocused: Bool

  private var cleanName: String { name.trimmingCharacters(in: .whitespaces).lowercased() }

  var body: some View {
    // One layout for both steps (name → code): every element keeps its place and only
    // the contents crossfade.
    VStack(spacing: 0) {
      BackHeader(title: "", back: back)
      Spacer(minLength: 8)

      ZStack {
        if code == nil {
          Hero(icon: "person.badge.plus", title: "Invite someone",
               subtitle: "They get a one-time code. Nobody joins until they use it.")
            .transition(.opacity)
        } else {
          Hero(icon: "checkmark", title: "Invite for \(prettyName(cleanName))",
               subtitle: "Send this link. It works once and expires in 7 days.")
            .transition(.opacity)
        }
      }

      ZStack {
        if let code {
          Text(code)
            .font(Typography.body.monospaced())
            .lineLimit(1)
            .truncationMode(.middle)
            .textSelection(.enabled)
            .padding(.horizontal, Spacing.card)
            .frame(maxWidth: .infinity, alignment: .leading)
            .transition(.opacity)
        } else {
          TextField("Their name", text: $name)
            .textFieldStyle(.plain)
            .font(Typography.body)
            .padding(.horizontal, Spacing.card)
            .focused($nameFocused)
            .onSubmit(create)
            .transition(.opacity)
        }
      }
      .frame(height: 38)
      .background(InputBackground())
      .padding(.top, Spacing.section)

      MessageSlot {
        if let error, code == nil {
          Text(error).font(Typography.caption).foregroundStyle(.orange).lineLimit(2).transition(.opacity)
        }
      }
      .padding(.top, 6)

      Button {
        if let code { copy(code) } else { create() }
      } label: {
        ZStack {
          // The wider label sizes the button, so switching labels never resizes it.
          Text("Create Invite").hidden()
          Text(code == nil ? (working ? "Creating…" : "Create Invite") : (copied ? "Copied" : "Copy Invite"))
        }
        .frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .tint(accent)
      .disabled(code == nil && (cleanName.isEmpty || working))
      .padding(.top, 10)

      Spacer(minLength: 8)
    }
    .padding(.horizontal, Spacing.edge)
    .padding(.bottom, 10)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .animation(.easeInOut(duration: 0.2), value: code)
    .animation(.easeInOut(duration: 0.15), value: error)
    .onAppear { nameFocused = true }
  }

  private func copy(_ code: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(inviteMessage(code), forType: .string)
    copied = true
    // Done here: show "Copied" for a moment, then return to the main screen.
    Task {
      try? await Task.sleep(nanoseconds: 800_000_000)
      back()
    }
  }

  private func inviteMessage(_ code: String) -> String {
    """
    Join my lembas pool: \(code)
    """
  }

  private func create() {
    guard !cleanName.isEmpty, !working else { return }
    working = true
    error = nil
    Task {
      do { code = try await store.invite(cleanName) }
      catch { self.error = error.localizedDescription }
      working = false
    }
  }
}

// "When I'm Away": my lending limits and when I count as away.
struct AwaySettingsView: View {
  @EnvironmentObject var store: Store
  let back: () -> Void

  var body: some View {
    VStack(alignment: .leading, spacing: Spacing.card) {
      BackHeader(title: "When I'm Away", back: back)

      VStack(alignment: .leading, spacing: 8) {
        Text("Lend until").font(Typography.title)
        PercentSlider(label: "5h", value: $store.policy.away5h, labelWidth: 34)
        PercentSlider(label: "Week", value: $store.policy.week, labelWidth: 34)
        Divider().padding(.vertical, 2)
        HStack {
          Text("Away after").font(Typography.body)
          Spacer()
          // Plain text value that opens a native menu (checkmark on the current choice).
          Menu {
            Picker("Away after", selection: $store.policy.awayAfterMinutes) {
              ForEach([15, 30, 60, 120], id: \.self) { Text(awayLabel($0)).tag($0) }
            }
            .pickerStyle(.inline)
            .labelsHidden()
          } label: {
            HStack(spacing: 3) {
              Text(awayLabel(store.policy.awayAfterMinutes))
              Image(systemName: "chevron.down").font(.system(size: 8, weight: .semibold))
            }
            .font(Typography.body)
            .foregroundStyle(.secondary)
          }
          .menuStyle(.borderlessButton)
          .menuIndicator(.hidden)
          .fixedSize()
        }
      }
      .padding(Spacing.card)
      .background(card)
    }
    .padding(.horizontal, inset)
  }
}

private func awayLabel(_ minutes: Int) -> String {
  minutes < 60 ? "\(minutes) min" : minutes == 60 ? "1 hour" : "\(minutes / 60) hours"
}

// After joining: one checklist. Connecting the subscription is required; opening at
// login is a choice. Rows tick themselves off as things complete.
struct SetupChecklistView: View {
  @EnvironmentObject var store: Store

  private var waiting: Bool { store.connectHint != nil && !store.connectHint!.hasPrefix("Couldn't") }

  var body: some View {
    VStack(spacing: 0) {
      PopoverHeader()
      Spacer(minLength: 12)
      Hero(icon: "checklist", title: "Finish setting up", subtitle: "Two quick things and you're in.")

      VStack(spacing: 0) {
        ChecklistRow(done: true, title: "Joined the pool",
                     detail: store.config.flatMap { URL(string: $0.url)?.host } ?? "") { EmptyView() }
        Divider().padding(.leading, 42)
        ChecklistRow(done: store.subscriptionConnected, title: "Connect subscription",
                     detail: store.subscriptionConnected ? "Connected" : store.connectHint ?? "Approve in your browser") {
          if !store.subscriptionConnected {
            if waiting {
              // No way to see the browser tab: if it was closed, Retry opens a fresh login.
              HStack(spacing: 8) {
                ProgressView().controlSize(.small)
                Button("Retry") { store.runConnect() }
                  .controlSize(.small)
              }
            } else {
              // A plain row button, like System Settings lists; blue is for the page's Done.
              Button("Connect") { store.runConnect() }
                .controlSize(.small)
            }
          }
        }
        Divider().padding(.leading, 42)
        ChecklistRow(done: store.opensAtLogin, title: "Open at login", detail: "Keeps lembas in your menu bar") {
          Toggle("Open at login", isOn: Binding(get: { store.opensAtLogin }, set: { store.setOpenAtLogin($0) }))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            .tint(accent)
        }
      }
      .background(card)
      .padding(.top, Spacing.section)

      Button { withAnimation(.easeInOut(duration: 0.25)) { store.askOpenAtLogin = false } } label: {
        Text("Done").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .tint(accent)
      .keyboardShortcut(.defaultAction)
      .disabled(!store.subscriptionConnected)
      .padding(.top, Spacing.card)

      // Right after joining, "wrong pool?": leave it and enter another invite. The row
      // keeps its space when hidden, so nothing moves.
      Button("Use a different invite") { Task { await store.goBackToJoin() } }
        .buttonStyle(.plain)
        .font(Typography.body)
        .foregroundStyle(.secondary)
        .padding(.top, 10)
        .opacity(store.inviteReturnable ? 1 : 0)
        .disabled(!store.inviteReturnable)
      Spacer(minLength: 12)
    }
    .padding(.horizontal, Spacing.edge)
    .padding(.vertical, Spacing.page)
    .animation(.spring(response: 0.35, dampingFraction: 0.8), value: store.subscriptionConnected)
    .animation(.spring(response: 0.35, dampingFraction: 0.8), value: store.opensAtLogin)
    .animation(.easeInOut(duration: 0.2), value: store.connectHint)
  }
}

// One checklist item: a circle that turns into a check when done, a title, an optional
// second line, and the control that completes it.
struct ChecklistRow<Trailing: View>: View {
  let done: Bool
  let title: String
  let detail: String
  @ViewBuilder var trailing: Trailing

  var body: some View {
    HStack(spacing: 10) {
      ZStack {
        Circle().strokeBorder(.tertiary, lineWidth: 1.5).opacity(done ? 0 : 1)
        Circle().fill(accent).scaleEffect(done ? 1 : 0.3).opacity(done ? 1 : 0)
        Image(systemName: "checkmark")
          .font(.system(size: 10, weight: .bold))
          .foregroundStyle(.white)
          .scaleEffect(done ? 1 : 0.3)
          .opacity(done ? 1 : 0)
      }
      .frame(width: 22, height: 22)
      VStack(alignment: .leading, spacing: 1) {
        Text(title).font(Typography.body)
        Text(detail)
          .font(Typography.caption)
          .foregroundStyle(detail.hasPrefix("Couldn't") ? Color.orange : Color.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
          .help(detail)
          .contentTransition(.opacity)
      }
      Spacer(minLength: 4)
      trailing
    }
    .padding(.horizontal, Spacing.card)
    .frame(height: 52) // every row the same: nothing moves as steps complete
  }
}

// Shown while the pool's first answer is on its way, instead of flashing the main screen.
struct LoadingView: View {
  var body: some View {
    VStack(spacing: 0) {
      PopoverHeader()
      Spacer()
      ProgressView().controlSize(.small)
      Spacer()
    }
    .padding(.horizontal, Spacing.edge)
    .padding(.vertical, Spacing.page)
  }
}

// Badge and name, as on the join, setup and loading screens. Identical everywhere.
struct PopoverHeader: View {
  var body: some View {
    HStack(spacing: 10) {
      AppBadge()
      Text("lembas" + (Profile.name.map { " · \($0)" } ?? "")).font(Typography.title)
      Spacer()
      Menu {
        Button("Quit lembas") { NSApp.terminate(nil) }
      } label: {
        Image(systemName: "gearshape")
      }
      .menuStyle(.borderlessButton)
      .menuIndicator(.hidden)
      .frame(width: 20)
    }
  }
}

struct LeaveView: View {
  @EnvironmentObject var store: Store
  let back: () -> Void

  var body: some View {
    VStack(spacing: 0) {
      BackHeader(title: "", back: back)
      Spacer(minLength: 8)
      Hero(icon: "rectangle.portrait.and.arrow.right", title: "Leave this pool?",
           subtitle: "Your subscription access is deleted from the pool, and Claude Code goes back to using only your own account.")
      MessageSlot(alignment: .top) {
        if let error = store.saveError {
          Text(error)
            .font(Typography.caption)
            .foregroundStyle(.orange)
            .multilineTextAlignment(.center)
            .lineLimit(2)
            .transition(.opacity)
        }
      }
      .padding(.top, Spacing.section)
      .animation(.easeInOut(duration: 0.15), value: store.saveError)
      Button(role: .destructive) {
        Task { if !(await store.leavePool()) { return } }
      } label: {
        Text(store.busy ? "Leaving…" : "Leave Pool").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .tint(.red)
      .disabled(store.busy)
      .padding(.top, Spacing.card)
      Button("Cancel", action: back)
        .buttonStyle(.plain)
        .foregroundStyle(.secondary)
        .padding(.top, 10)
      Spacer(minLength: 8)
    }
    .padding(.horizontal, Spacing.edge)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
  }
}

struct MainView: View {
  @EnvironmentObject var store: Store
  @State private var selected: String?
  @State private var inviting = false
  @State private var awaySettings = false
  @State private var leaving = false

  private var onHome: Bool { selected == nil && !inviting && !awaySettings && !leaving }

  private func go(_ change: () -> Void) {
    withAnimation(.easeInOut(duration: 0.2), change)
  }

  var body: some View {
    home
      .opacity(onHome ? 1 : 0)
      .allowsHitTesting(onHome)
      // Pages overlay the home screen inside the root's fixed frame.
      .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
      .overlay(alignment: .top) {
        if let name = selected, let i = store.lendingMembers.firstIndex(where: { $0.name == name }) {
          PersonDetail(
            member: $store.lendingMembers[i],
            source: store.borrowSources.first { $0.name == name },
            lentThisWeek: store.borrowedWeekByCaller[name] ?? 0,
            borrowedThisWeek: store.borrowedByMeWeekByOwner[name] ?? 0,
            remove: store.canInvite ? {
              withAnimation(.easeInOut(duration: 0.2)) { selected = nil }
              Task { await store.removeMember(name) }
            } : nil,
            back: { withAnimation(.easeInOut(duration: 0.2)) { selected = nil } }
          )
          .padding(.vertical, Spacing.page)
          .transition(.move(edge: .trailing).combined(with: .opacity))
        } else if inviting {
          InviteView(back: { go { inviting = false } })
            .padding(.vertical, Spacing.page)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        } else if awaySettings {
          AwaySettingsView(back: { go { awaySettings = false } })
            .padding(.vertical, Spacing.page)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        } else if leaving {
          LeaveView(back: { go { leaving = false } })
            .padding(.vertical, Spacing.page)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        }
      }
      .clipped()
      .onChange(of: store.settingKey) { store.scheduleSave() }
  }

  private var home: some View {
    VStack(alignment: .leading, spacing: 0) {
      header
      if let problem = store.online ? store.saveError : store.statusLine {
        Notice(text: problem).padding(.horizontal, inset).padding(.top, 8)
      }
      lendingStatus
        .padding(.horizontal, Spacing.edge)
        .padding(.top, Spacing.card)
      SectionHeader(title: "This week")
        .padding(.top, Spacing.section)
      HStack(spacing: 8) {
        WeekTile(title: "Lent", icon: "arrow.up.right", value: store.borrowedWeekTotal)
        WeekTile(title: "Borrowed", icon: "arrow.down.left", value: store.borrowedByMeWeekTotal)
      }
      .padding(.horizontal, Spacing.edge)
      SectionHeader(title: "Your usage")
        .padding(.top, Spacing.section)
      // Anthropic's own live numbers for this subscription (what lending limits use).
      VStack(spacing: 8) {
        UsageBar(label: "5h", percent: store.utilizationFiveHour, lent: store.lentFiveHour)
        UsageBar(label: "Week", percent: store.utilizationSevenDay, lent: store.lentSevenDay)
        HStack(spacing: 12) {
          Label { Text("You") } icon: { Circle().fill(accent).frame(width: 7, height: 7) }
          Label { Text("Friends") } icon: { Circle().fill(friendsColor).frame(width: 7, height: 7) }
          Spacer()
        }
        .font(Typography.caption)
        .foregroundStyle(.secondary)
        .padding(.leading, 42)
      }
      .padding(Spacing.card)
      .background(card)
      .padding(.horizontal, Spacing.edge)
      if !store.lendingMembers.isEmpty || store.canInvite {
        SectionHeader(title: "People")
          .padding(.top, Spacing.section)
        ScrollView {
          VStack(alignment: .leading, spacing: 0) {
            ForEach(store.lendingMembers) { member in
              PersonRow(member: member, source: store.borrowSources.first { $0.name == member.name }) {
                go { selected = member.name }
              }
            }
            if store.canInvite {
              HoverRow(action: { go { inviting = true } }) {
                HStack(spacing: 10) {
                  Image(systemName: "plus")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(accent)
                    .frame(width: 28, height: 28)
                    .background(Circle().fill(.quaternary))
                  Text("Invite to Pool…").font(Typography.title)
                }
              }
            }
          }
        }
        .frame(maxHeight: .infinity)
      } else {
        Spacer(minLength: 0)
      }
      if let update = store.update {
        MenuSeparator()
        HoverRow(action: { Task { await store.installUpdate() } }) {
          HStack(spacing: 8) {
            Image(systemName: "arrow.down.circle.fill").foregroundStyle(accent)
            Text(store.updateStatus ?? (update.version == Store.currentVersion ? "Install latest build…" : "Update to \(update.version)…"))
          }
        }
      } else if let status = store.updateStatus {
        MenuSeparator()
        Text(status).font(Typography.caption).foregroundStyle(.secondary).padding(.horizontal, inset)
      }
    }
    .padding(.vertical, 10)
  }

  // Away switch ("I'm done for today" / "I'm back"; also turns on by itself when idle),
  // with the away limits one row below.
  private var lendingStatus: some View {
    VStack(spacing: 0) {
      HStack(spacing: 10) {
        Image(systemName: "moon.fill")
          .font(.system(size: 12, weight: .semibold))
          .foregroundStyle(store.away ? Color.white : Color.secondary)
          .frame(width: 28, height: 28)
          .background(Circle().fill(store.away ? AnyShapeStyle(accent) : AnyShapeStyle(.quaternary)))
        VStack(alignment: .leading, spacing: 1) {
          Text(store.away ? "Away" : "Working").font(Typography.title)
          Text(store.away ? "Friends can borrow" : "Away after \(store.policy.awayAfterMinutes) min idle")
            .font(Typography.caption)
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 4)
        Toggle("Away", isOn: Binding(get: { store.away }, set: { on in Task { await store.setAway(on) } }))
          .labelsHidden()
          .toggleStyle(.switch)
          .controlSize(.small)
          .tint(accent)
      }
      .padding(Spacing.card)
      Divider().padding(.leading, 48)
      Button { go { awaySettings = true } } label: {
        HStack {
          Text("Lending limits").font(Typography.caption).foregroundStyle(.secondary)
          Spacer()
          Image(systemName: "chevron.right")
            .font(.system(size: 10, weight: .semibold))
            .foregroundStyle(.tertiary)
        }
        .padding(.leading, 48)
        .padding(.trailing, 10)
        .padding(.vertical, 7)
        .contentShape(Rectangle())
      }
      .buttonStyle(.plain)
    }
    .background(card)
  }

  // Title row with the main switch on the right, like the Wi‑Fi and Bluetooth menus.
  private var header: some View {
    HStack(spacing: 10) {
      AppBadge()
      VStack(alignment: .leading, spacing: 1) {
        Text("lembas" + (Profile.name.map { " · \($0)" } ?? "")).font(Typography.title)
        Text(subtitle)
          .font(Typography.caption)
          .foregroundStyle(store.routedThroughPool ? Color.secondary : Color.orange)
      }
      Spacer()
      Toggle("Pool fallback", isOn: Binding(get: { store.routedThroughPool }, set: { store.setRouted($0) }))
        .labelsHidden()
        .toggleStyle(.switch)
        .tint(accent)
        .help("Pool fallback: borrow from friends when you hit your limit")
      Menu {
        // Account, then app, then the ways out — the usual macOS menu order.
        if let me = store.me { Text("Signed in as \(prettyName(me))") }
        Button(store.subscriptionConnected ? "Reconnect Subscription…" : "Connect Subscription…") { store.runConnect() }
        Divider()
        // Borrowed requests go through the private path: the pool lends the token but
        // can't read the request or the answer. Not a setting; the status line says
        // when a pool can't do it.
        if store.online && !store.poolSupportsPrivate && !store.relayForced {
          Text("Your pool can't lend privately yet, so borrowed requests use its relay.")
          Divider()
        }
        Button("Check for Updates…") { Task { await store.checkForUpdate(force: true) } }
        Text("Version \(Store.currentVersion) (\(Store.currentBuild))")
        Divider()
        Button("Leave Pool…") { go { leaving = true } }
        Button("Quit lembas") { NSApp.terminate(nil) }
          .keyboardShortcut("q")
      } label: {
        Image(systemName: "gearshape")
      }
      .menuStyle(.borderlessButton)
      .menuIndicator(.hidden)
      .frame(width: 20)
      .help("Settings")
    }
    .padding(.horizontal, inset)
  }

  private var subtitle: String {
    let who = store.me.map { prettyName($0) + " · " } ?? ""
    let privately = store.poolSupportsPrivate && !store.relayForced
    let mode = store.routedThroughPool ? (privately ? "Fallback on · private" : "Fallback on · relay") : "Fallback off"
    return who + mode
  }
}

private func dollars(_ value: Double) -> String {
  String(format: "$%.2f", value)
}

private func oneDecimal(_ value: Double) -> String {
  String(format: "%.1f", value)
}

private func prettyName(_ name: String) -> String {
  guard let first = name.first else { return name }
  return first.uppercased() + name.dropFirst()
}

// Hands over the NSWindow a SwiftUI view lives in.
struct WindowAccessor: NSViewRepresentable {
  let found: (NSWindow) -> Void
  func makeNSView(context: Context) -> NSView { WindowView(found: found) }
  func updateNSView(_ view: NSView, context: Context) {}

  final class WindowView: NSView {
    let found: (NSWindow) -> Void
    init(found: @escaping (NSWindow) -> Void) {
      self.found = found
      super.init(frame: .zero)
    }
    required init?(coder: NSCoder) { nil }
    override func viewDidMoveToWindow() {
      super.viewDidMoveToWindow()
      if let window { found(window) }
    }
  }
}

// Keeps the menu bar popover up while `pinned` (waiting for the browser login).
// MenuBarExtra hides its window as soon as another app comes forward and offers no
// setting for that, so the window gets a subclass whose orderOut/close do nothing
// while pinned and behave normally otherwise. Only touched on the main thread.
enum PopoverPin {
  static var pinned = false {
    didSet { if !pinned && closeWasIgnored { closeOnNextClickOutside() } }
  }
  private static weak var window: NSWindow?
  static var isShowing: Bool { window?.isVisible == true }
  private static var closeWasIgnored = false
  private static var monitors: [Any] = []

  // SwiftUI thinks the popover closed when we ignored its close request, so it won't
  // close it on outside clicks anymore. Do that ourselves once, then hand back control.
  private static func closeOnNextClickOutside() {
    closeWasIgnored = false
    let close = {
      window?.orderOut(nil)
      monitors.forEach { NSEvent.removeMonitor($0) }
      monitors = []
    }
    if let monitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown], handler: { _ in close() }) {
      monitors.append(monitor)
    }
  }

  static func attach(_ window: NSWindow) {
    let base: AnyClass = type(of: window)
    let baseName = NSStringFromClass(base)
    guard !baseName.hasPrefix("LembasPinned_") else { return }
    let name = "LembasPinned_" + baseName
    var pinnedClass: AnyClass? = NSClassFromString(name)
    if pinnedClass == nil, let made = objc_allocateClassPair(base, name, 0) {
      override(#selector(NSWindow.orderOut(_:)), in: made, base: base)
      override(#selector(NSWindow.close), in: made, base: base)
      objc_registerClassPair(made)
      pinnedClass = made
    }
    if let pinnedClass { object_setClass(window, pinnedClass) }
    Self.window = window
  }

  // The implementation each overridden selector had before us, for forwarding.
  private static var originals: [Selector: IMP] = [:]

  private static func override(_ selector: Selector, in subclass: AnyClass, base: AnyClass) {
    guard let method = class_getInstanceMethod(base, selector) else { return }
    originals[selector] = method_getImplementation(method)
    // Not imp_implementationWithBlock: a Swift block IMP retains its (object-typed)
    // arguments, but AppKit calls close/orderOut with non-object senders too — that
    // retain crashed the app on every quit (SIGTRAP in swift_unknownObjectRetain
    // under -[NSWindow _closeForTermination]). A capture-free @convention(c) IMP
    // matches the original method's ABI exactly: nothing captured, nothing retained.
    typealias Msg = @convention(c) (AnyObject, Selector, AnyObject?) -> Void
    let replacement: Msg = { window, sel, sender in
      if PopoverPin.pinned {
        PopoverPin.closeWasIgnored = true
        return
      }
      if let imp = PopoverPin.originals[sel] {
        unsafeBitCast(imp, to: Msg.self)(window, sel, sender)
      }
    }
    class_addMethod(subclass, selector, unsafeBitCast(replacement, to: IMP.self), method_getTypeEncoding(method))
  }
}

// macOS runs a downloaded app that wasn't moved in Finder from a temporary, read-only
// copy ("App Translocation"). lembas needs a permanent home: its agent watches the app's
// path, and updates replace the app in place. So it asks to move itself first.
enum AppLocation {
  static let isTranslocated = Bundle.main.bundlePath.contains("/AppTranslocation/")

  // Where the app really is (e.g. ~/Downloads/lembas.app), via Security's
  // SecTranslocateCreateOriginalPathForURL, which Swift doesn't import.
  static func originalURL() -> URL? {
    typealias Original = @convention(c) (CFURL, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFURL>?
    guard let security = dlopen("/System/Library/Frameworks/Security.framework/Security", RTLD_NOW),
          let symbol = dlsym(security, "SecTranslocateCreateOriginalPathForURL") else { return nil }
    let original = unsafeBitCast(symbol, to: Original.self)
    return original(Bundle.main.bundleURL as CFURL, nil).map { $0.takeRetainedValue() as URL }
  }

  // Copies the app to /Applications (or ~/Applications), clears the "downloaded" mark the
  // person already approved, moves the downloaded copy to the Trash, and relaunches.
  static func moveToApplications() throws {
    guard let original = originalURL() else { throw LoginError("couldn't find where lembas was downloaded") }
    let fm = FileManager.default
    let system = URL(fileURLWithPath: "/Applications")
    let folder = fm.isWritableFile(atPath: system.path) ? system : fm.homeDirectoryForCurrentUser.appendingPathComponent("Applications")
    try fm.createDirectory(at: folder, withIntermediateDirectories: true)
    let destination = folder.appendingPathComponent("lembas.app")
    if fm.fileExists(atPath: destination.path) { try fm.removeItem(at: destination) }
    try fm.copyItem(at: original, to: destination)
    let xattr = Process()
    xattr.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
    xattr.arguments = ["-dr", "com.apple.quarantine", destination.path]
    try xattr.run()
    xattr.waitUntilExit()
    try? fm.trashItem(at: original, resultingItemURL: nil)

    // Start the moved copy ourselves, then quit. (A helper script started from the
    // translocated copy gets stopped along with it, so it can't do the relaunch.)
    let launch = NSWorkspace.OpenConfiguration()
    launch.createsNewApplicationInstance = true
    launch.environment = ProcessInfo.processInfo.environment.filter { ["LEMBAS_PROFILE", "LEMBAS_APPEARANCE"].contains($0.key) }
    NSWorkspace.shared.openApplication(at: destination, configuration: launch) { _, _ in
      DispatchQueue.main.async { NSApp.terminate(nil) }
    }
  }
}

struct MoveToApplicationsView: View {
  @State private var error: String?

  var body: some View {
    VStack(spacing: 0) {
      PopoverHeader()
      Spacer(minLength: 12)
      Hero(icon: "folder.fill", title: "Move lembas to Applications",
           subtitle: "It needs a permanent home to update itself and keep Claude Code working.")
      MessageSlot(alignment: .top) {
        if let error {
          Text(error).font(Typography.caption).foregroundStyle(.orange).multilineTextAlignment(.center).lineLimit(2)
        }
      }
      .padding(.top, Spacing.section)
      Button {
        do { try AppLocation.moveToApplications() } catch { self.error = "Couldn't move it: \(error.localizedDescription)" }
      } label: {
        Text("Move to Applications").frame(maxWidth: .infinity)
      }
      .buttonStyle(.borderedProminent)
      .controlSize(.large)
      .tint(accent)
      .keyboardShortcut(.defaultAction)
      .padding(.top, Spacing.card)
      Spacer(minLength: 12)
    }
    .padding(.horizontal, Spacing.edge)
    .padding(.vertical, Spacing.page)
  }
}

// Every screen shares one fixed size: the menu bar window can't resize smoothly (it
// jumps and misplaces itself), so screens crossfade inside the same frame instead.
struct RootView: View {
  @EnvironmentObject var store: Store

  var body: some View {
    ZStack {
      switch store.screen {
      case .move: MoveToApplicationsView().transition(.opacity)
      case .join: SetupView().transition(.opacity)
      case .loading: LoadingView().transition(.opacity)
      case .setup: SetupChecklistView().transition(.opacity)
      case .main: MainView().transition(.opacity)
      }
    }
    .frame(width: 320, height: 500)
    .font(Typography.body)
    .background(popoverBackground.ignoresSafeArea())
    .background(WindowAccessor { PopoverPin.attach($0) })
    .animation(.easeInOut(duration: 0.25), value: store.screen)
    .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { note in
      if !SetupWindow.owns(note.object as? NSWindow) { SetupWindow.close() } // they found the menu bar icon
      Task {
        await store.refresh()
        await store.checkForUpdate()
      }
    }
  }
}

// Receives lembas:// links (also when they launch the app) and hands them to the store.
@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
  static var store: Store?

  // SwiftUI only builds the menu's content on first open; create the store at launch
  // so refreshing, cleanup and update checks start right away.
  func applicationDidFinishLaunching(_ notification: Notification) {
    // Follows the system appearance; LEMBAS_APPEARANCE=light|dark overrides it for this
    // copy (handy to compare both side by side).
    switch ProcessInfo.processInfo.environment["LEMBAS_APPEARANCE"] {
    case "light": NSApp.appearance = NSAppearance(named: .aqua)
    case "dark": NSApp.appearance = NSAppearance(named: .darkAqua)
    default: break
    }
    let store = Store.shared
    // Mid-setup (not joined yet, or the checklist isn't done): open the popover by
    // itself so setup picks up where it left off. Once set up, launch quietly.
    Task { @MainActor in
      for _ in 0..<50 where store.config != nil && !store.loaded {
        try? await Task.sleep(nanoseconds: 100_000_000)
      }
      if [.move, .join, .setup].contains(store.screen) { SetupWindow.show() }
    }
  }

  func application(_ application: NSApplication, open urls: [URL]) {
    Task { @MainActor in
      // At launch the store may not exist yet; give SwiftUI a moment to create it.
      for _ in 0..<20 where Self.store == nil { try? await Task.sleep(nanoseconds: 100_000_000) }
      urls.forEach { Self.store?.handleInviteLink($0) }
    }
  }
}

// First run (and an invite link before joining) shows a small hint window pointing at
// the menu bar icon: an app that only adds an icon leaves new people wondering where it
// went. Setup itself happens in the menu bar popover. The hint closes as soon as the
// popover opens (or with its close button).
@MainActor
enum SetupWindow {
  private static var window: NSWindow?

  static func show() {
    if window == nil {
      let made = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 300, height: 270),
                          styleMask: [.titled, .closable, .fullSizeContentView], backing: .buffered, defer: false)
      made.titlebarAppearsTransparent = true
      made.titleVisibility = .hidden
      made.isReleasedWhenClosed = false
      made.contentView = NSHostingView(rootView: MenuBarHintView().environmentObject(Store.shared))
      made.center()
      window = made
    }
    window?.makeKeyAndOrderFront(nil)
    NSApp.activate(ignoringOtherApps: true)
  }

  static func close() {
    window?.close()
    window = nil
  }

  static func owns(_ other: NSWindow?) -> Bool { other != nil && other === window }

  // Our menu bar icon. macOS keeps a status-item window per display, most of them
  // parked off screen; the real one sits on screen with a height.
  static func statusButton() -> NSStatusBarButton? {
    func find(_ view: NSView) -> NSStatusBarButton? {
      if let button = view as? NSStatusBarButton { return button }
      return view.subviews.lazy.compactMap(find).first
    }
    return NSApp.windows
      .filter { String(describing: type(of: $0)).contains("StatusBarWindow") && $0.frame.height > 0 && $0.frame.minY >= 0 }
      .lazy.compactMap { $0.contentView.flatMap(find) }.first
  }

  // Direction from the hint window to the icon, as a clockwise rotation from "right".
  static func angleToIcon() -> Angle? {
    guard let window, let icon = statusButton()?.window?.frame else { return nil }
    let dx = icon.midX - window.frame.midX
    let dy = icon.midY - window.frame.midY // screen y grows upward
    return .radians(-atan2(dy, dx))
  }
}

struct MenuBarHintView: View {
  @EnvironmentObject var store: Store
  @State private var arrow = Angle.degrees(-45) // up and to the right until we know better
  private let placed = Timer.publish(every: 0.5, on: .main, in: .common).autoconnect() // icon may appear late

  var body: some View {
    VStack(spacing: 0) {
      Spacer(minLength: 12)
      Image(nsImage: LembasLogo.tile(size: 56))
      Text("lembas is in your menu bar")
        .font(Typography.title)
        .padding(.top, Spacing.section)
      Text(store.setupInvite.isEmpty ? "Click it to join your pool." : "Click it to join — your invite is filled in.")
        .font(Typography.body)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .padding(.top, Spacing.header)
      HStack(spacing: 8) {
        Image(nsImage: LembasLogo.menuBar)
        Image(systemName: "arrow.right")
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.secondary)
          .rotationEffect(arrow) // points at the icon wherever the window is
        Text("menu bar").font(Typography.caption).foregroundStyle(.secondary)
      }
      .padding(.horizontal, 12)
      .padding(.vertical, 6)
      .background(Capsule().fill(.quaternary))
      .padding(.top, Spacing.section)
      .onReceive(NotificationCenter.default.publisher(for: NSWindow.didMoveNotification)) { note in
        if SetupWindow.owns(note.object as? NSWindow), let angle = SetupWindow.angleToIcon() { arrow = angle }
      }
      .onReceive(placed) { _ in
        if let angle = SetupWindow.angleToIcon() { arrow = angle }
      }
      Spacer(minLength: 12)
    }
    .padding(.horizontal, Spacing.edge + 10)
    .frame(width: 300, height: 270)
    .background(popoverBackground.ignoresSafeArea())
  }
}

@main
struct PoolBarApp: App {
  @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate
  @StateObject private var store = Store.shared
  var body: some Scene {
    MenuBarExtra {
      RootView().environmentObject(store)
    } label: {
      Image(nsImage: LembasLogo.menuBar)
        .accessibilityLabel("lembas")
    }
    .menuBarExtraStyle(.window)
  }
}
