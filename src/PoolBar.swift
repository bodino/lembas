// lembas bar — a macOS menu bar app for the lembas pool.
// Shows your live sharing state and lets you lend to individual people.
// Config: ~/.config/lembas.json  {"url": "http://…:8787", "token": "pool-…"}

import AppKit
import Combine
import ServiceManagement
import SwiftUI

struct Config: Codable {
  var url: String
  var token: String
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
  var reason: String // away | working | off | unconnected | parked | unknown | full
  var availablePoints: Double
  var id: String { name }
  var displayName: String { prettyName(name) }
  var available: Bool { reason == "away" || reason == "working" }

  var chip: String {
    switch reason {
    case "away", "working": return "\(Int(availablePoints)) pts"
    case "full": return "Full"
    case "parked": return "Paused"
    case "unconnected": return "Not set up"
    case "unknown": return "—"
    default: return "Off"
    }
  }

  var explanation: String {
    switch reason {
    case "away": return "Away · \(Int(availablePoints)) pts available"
    case "working": return "Working · \(Int(availablePoints)) pts available"
    case "full": return "At their limit"
    case "parked": return "Hit their own limit"
    case "unconnected": return "Not set up yet"
    case "unknown": return "Usage unavailable"
    default: return "Not lending to you"
    }
  }
}

@MainActor
final class Store: ObservableObject {
  @Published var config: Config?
  @Published var setupInvite = ""
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
  @Published var policy = LendPolicy()
  @Published var away = false
  @Published var statusLine = "Not connected."
  @Published var busy = false
  @Published var lastApplied: String?
  @Published var subscriptionConnected = false
  @Published var routedThroughPool = false
  @Published var connectHint: String?
  @Published private var savedSettings: [String] = []

  @Published var saveError: String?
  @Published var canInvite = false

  private var refreshing = false
  private var pendingSave: Task<Void, Never>?

  var settingKey: [String] { lendingMembers.map(\.setting) + [policy.setting] }
  var hasChanges: Bool { settingKey != savedSettings }

  static let configURL = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".config/lembas.json")

  // The app used to be called claudus; carry an existing install over once.
  static let legacyConfigURL = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".config/claudus-bar.json")
  static let legacyAgentLabel = "com.claudus.agent"

  init() {
    if !FileManager.default.fileExists(atPath: Self.configURL.path) {
      try? FileManager.default.moveItem(at: Self.legacyConfigURL, to: Self.configURL)
    }
    if let data = try? Data(contentsOf: Self.configURL),
       let cfg = try? JSONDecoder().decode(Config.self, from: data) {
      config = cfg
      Task { try? await ensureAgentInstalled() }
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

  // Joining from an invite code like "https://mac.tail1234.ts.net/abcd-efgh-…" (or a
  // tailnet "100.1.2.3:8787/…"): swap the one-time code for this member's pool token,
  // then install the bundled agent and point Claude Code at it.
  func join() async {
    var raw = setupInvite.trimmingCharacters(in: .whitespacesAndNewlines)
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
      saveConfig(Config(url: pool, token: token))
      try await ensureAgentInstalled(restart: true)
      setRouted(true)
      try? SMAppService.mainApp.register() // keep the menu bar icon after a restart
      setupInvite = ""
      await refresh()
      runConnect()
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
    if http.statusCode >= 400 {
      let msg = ((obj["error"] as? [String: Any])?["message"] as? String) ?? "HTTP \(http.statusCode)"
      throw NSError(domain: "lembas", code: http.statusCode,
                    userInfo: [NSLocalizedDescriptionKey: msg])
    }
    return obj
  }

  func refresh() async {
    guard config != nil, !refreshing else { return }
    refreshing = true
    reloadRoute()
    defer { refreshing = false }
    do {
      let obj = try await request("GET", "/pool")
      me = obj["you"] as? String
      canInvite = obj["canInvite"] as? Bool ?? false
      online = true
      statusLine = "Connected."

      guard let me, let user = obj[me] as? [String: Any] else {
        online = false
        statusLine = "Signed in, but this token is not in the pool."
        return
      }

      subscriptionConnected = user["subscriptionConnected"] as? Bool ?? false
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
                       availablePoints: number(row["availablePoints"]))
        }.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
      } else {
        borrowSources = []
      }
    } catch {
      online = false
      statusLine = "Pool unreachable: \(error.localizedDescription)"
    }
  }

  // ----- Claude Code routing: direct, or through the pool -----

  static let claudeSettings = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent(".claude/settings.json")
  static let localAgentURL = "http://127.0.0.1:8788"

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

  func runConnect() {
    guard let cfg = config else { return }
    connectHint = "Approve in your browser…"
    Task {
      do {
        try await SubscriptionLogin.run(pool: cleanURL(cfg.url), poolToken: cfg.token)
        connectHint = nil
        await refresh()
      } catch {
        connectHint = "Couldn't connect: \(error.localizedDescription)"
      }
    }
  }

  // ----- the bundled agent (Contents/MacOS/lembas-agent), run by launchd -----

  static let agentLabel = "com.lembas.agent"
  static let agentPlist = FileManager.default.homeDirectoryForCurrentUser
    .appendingPathComponent("Library/LaunchAgents/com.lembas.agent.plist")
  private var agentBinary: String { Bundle.main.bundleURL.appendingPathComponent("Contents/MacOS/lembas-agent").path }

  // launchd keeps the agent running (and restarts it) even when this app is closed.
  // Rewrites the job when it points anywhere else, e.g. at the old Node agent or an
  // app copy that moved.
  func ensureAgentInstalled(restart: Bool = false) async throws {
    guard FileManager.default.isExecutableFile(atPath: agentBinary) else { return }
    let legacyPlist = Self.agentPlist.deletingLastPathComponent().appendingPathComponent("\(Self.legacyAgentLabel).plist")
    if FileManager.default.fileExists(atPath: legacyPlist.path) {
      // Free port 8788 from the old claudus agent before ours takes over.
      try? await runShell("launchctl bootout gui/$(id -u)/$1 2>/dev/null; sleep 1", Self.legacyAgentLabel)
      try? FileManager.default.removeItem(at: legacyPlist)
    }
    let current = (NSDictionary(contentsOf: Self.agentPlist)?["ProgramArguments"] as? [String])?.first
    if current == agentBinary {
      if restart { try await runShell("launchctl kickstart -k gui/$(id -u)/$1", Self.agentLabel) }
      return
    }
    let firstInstall = !FileManager.default.fileExists(atPath: Self.agentPlist.path)
    let logs = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/lembas-agent.log").path
    let plist: [String: Any] = [
      "Label": Self.agentLabel,
      "ProgramArguments": [agentBinary],
      "RunAtLoad": true,
      "KeepAlive": true,
      "StandardOutPath": logs,
      "StandardErrorPath": logs,
    ]
    try FileManager.default.createDirectory(at: Self.agentPlist.deletingLastPathComponent(), withIntermediateDirectories: true)
    try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0).write(to: Self.agentPlist)
    // The pause lets the old agent release its port before the new one starts.
    try await runShell("launchctl bootout gui/$(id -u)/$1 2>/dev/null && sleep 1; launchctl bootstrap gui/$(id -u) \"$2\"",
                       Self.agentLabel, Self.agentPlist.path)
    if firstInstall { setRouted(true) } // fresh Terminal install: point Claude Code at the agent
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
      try? await Task.sleep(nanoseconds: 30_000_000_000)
    }
  }
}

struct SetupView: View {
  @EnvironmentObject var store: Store
  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(spacing: 10) {
        AppBadge()
        VStack(alignment: .leading, spacing: 1) {
          Text("lembas").font(Typography.title)
          Text("Join a pool").font(Typography.caption).foregroundStyle(.secondary)
        }
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

      VStack(alignment: .leading, spacing: 8) {
        Text("Invite code").font(Typography.caption).foregroundStyle(.secondary)
        TextField("https://….ts.net/abcd-efgh-…", text: $store.setupInvite)
          .textFieldStyle(.roundedBorder)
          .font(Typography.body.monospaced())
          .disabled(store.busy)
          .onSubmit { Task { await store.join() } }
        if let status = store.joinStatus {
          HStack(spacing: 6) {
            ProgressView().controlSize(.small)
            Text(status).font(Typography.caption).foregroundStyle(.secondary)
          }
        }
        if let error = store.joinError {
          Text(error)
            .font(Typography.caption)
            .foregroundStyle(.orange)
            .fixedSize(horizontal: false, vertical: true)
        }
        HStack {
          Spacer()
          Button("Join") { Task { await store.join() } }
            .buttonStyle(.borderedProminent)
            .tint(accent)
            .keyboardShortcut(.defaultAction)
            .disabled(store.setupInvite.trimmingCharacters(in: .whitespaces).isEmpty || store.busy)
        }
      }
      .padding(10)
      .background(card)

      Text("Paste the invite code a friend sent you. lembas sets everything else up.")
        .font(Typography.caption)
        .foregroundStyle(.secondary)
        .fixedSize(horizontal: false, vertical: true)
    }
    .padding(14)
    .frame(width: 320)
    .font(Typography.body)
    .background(popoverBackground.ignoresSafeArea())
  }
}

// Layout follows the system menu bar popovers (Wi‑Fi, Bluetooth): 14pt content inset,
// inset separators, rows that highlight on hover. Neutral surfaces and system text
// colors throughout; the system accent color for controls. Lend (↗) vs borrow (↙) is told
// apart by the arrow, not by color.
private let inset: CGFloat = 14

// The app's whole type scale. Icons size their glyphs separately.
enum Typography {
  static let title = Font.system(size: 13, weight: .semibold)  // names, titles, Working/Away
  static let body = Font.system(size: 12)                      // row labels, controls, values
  static let caption = Font.system(size: 11)                   // secondary lines, tags, slider labels
  static let figure = Font.system(size: 20, weight: .semibold, design: .rounded) // the two weekly totals
}
private let accent = Color.accentColor // follows System Settings › Appearance

// The menu bar window is see-through glass, so whatever is behind it (often a light
// wallpaper) washes the content out. A solid window background keeps text and
// controls at full contrast in light and dark mode.
private let popoverBackground = Color(nsColor: .windowBackgroundColor)

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
    .background(Capsule().fill(active ? AnyShapeStyle(.quaternary) : AnyShapeStyle(.quaternary.opacity(0.5))))
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
    .padding(10)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(card)
  }
}

private var card: some View {
  RoundedRectangle(cornerRadius: 10, style: .continuous)
    .fill(.quaternary.opacity(0.5)) // .quinary on macOS 14+
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
      .padding(.horizontal, inset)
      .padding(.bottom, 2)
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
      .padding(10)
      .background(card)

      VStack(alignment: .leading, spacing: 8) {
        sectionLabel("\(member.displayName) lends you", "arrow.down.left")
        Text(source?.explanation ?? "Not lending to you")
          .font(Typography.caption)
          .foregroundStyle(.secondary)
          .fixedSize(horizontal: false, vertical: true)
      }
      .padding(10)
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
    VStack(spacing: 0) {
      HStack {
        Button(action: back) {
          Image(systemName: "chevron.left")
            .font(.system(size: 12, weight: .semibold))
            .frame(width: 22, height: 22)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .keyboardShortcut(.cancelAction)
        Spacer()
      }

      Spacer(minLength: 8)

      if let code {
        hero(icon: "checkmark", title: "Invite for \(prettyName(cleanName))",
             subtitle: "Send this code. It works once and expires in 7 days.")
        Text(code)
          .font(Typography.title.monospaced())
          .lineLimit(1)
          .minimumScaleFactor(0.7)
          .textSelection(.enabled)
          .padding(.horizontal, 10)
          .frame(maxWidth: .infinity)
          .padding(.vertical, 12)
          .background(field)
          .padding(.top, 18)
        Button {
          NSPasteboard.general.clearContents()
          NSPasteboard.general.setString(inviteMessage(code), forType: .string)
          copied = true
        } label: {
          Label(copied ? "Copied" : "Copy Invite", systemImage: copied ? "checkmark" : "doc.on.doc")
            .frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .tint(accent)
        .padding(.top, 10)
      } else {
        hero(icon: "person.badge.plus", title: "Invite someone",
             subtitle: "They get a one-time code. Nobody joins until they use it.")
        TextField("Their name", text: $name)
          .textFieldStyle(.plain)
          .font(Typography.body)
          .padding(.horizontal, 12)
          .padding(.vertical, 10)
          .background(field)
          .focused($nameFocused)
          .onSubmit(create)
          .padding(.top, 18)
        if let error {
          Text(error)
            .font(Typography.caption)
            .foregroundStyle(.orange)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.top, 6)
        }
        Button(action: create) {
          Text(working ? "Creating…" : "Create Invite").frame(maxWidth: .infinity)
        }
        .buttonStyle(.borderedProminent)
        .controlSize(.large)
        .tint(accent)
        .disabled(cleanName.isEmpty || working)
        .padding(.top, 10)
      }

      Spacer(minLength: 8)
    }
    .padding(.horizontal, inset + 6)
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .onAppear { nameFocused = true }
  }

  private func hero(icon: String, title: String, subtitle: String) -> some View {
    VStack(spacing: 6) {
      Image(systemName: icon)
        .font(.system(size: 20, weight: .semibold))
        .foregroundStyle(.white)
        .frame(width: 48, height: 48)
        .background(Circle().fill(accent))
        .padding(.bottom, 6)
      Text(title).font(Typography.title)
      Text(subtitle)
        .font(Typography.body)
        .foregroundStyle(.secondary)
        .multilineTextAlignment(.center)
        .fixedSize(horizontal: false, vertical: true)
    }
  }

  // A solid input surface that stays readable on the translucent menu bar window.
  private var field: some View {
    RoundedRectangle(cornerRadius: 8, style: .continuous)
      .fill(Color(nsColor: .textBackgroundColor))
      .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(.quaternary))
  }

  private func inviteMessage(_ code: String) -> String {
    """
    Join my lembas pool: open lembas and paste this invite code.
    \(code)
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
    VStack(alignment: .leading, spacing: 10) {
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
      .padding(10)
      .background(card)
    }
    .padding(.horizontal, inset)
  }
}

private func awayLabel(_ minutes: Int) -> String {
  minutes < 60 ? "\(minutes) min" : minutes == 60 ? "1 hour" : "\(minutes / 60) hours"
}

struct MainView: View {
  @EnvironmentObject var store: Store
  @State private var selected: String?
  @State private var inviting = false
  @State private var awaySettings = false

  private var onHome: Bool { selected == nil && !inviting && !awaySettings }

  private func go(_ change: () -> Void) {
    withAnimation(.easeInOut(duration: 0.2), change)
  }

  var body: some View {
    home
      .opacity(onHome ? 1 : 0)
      .allowsHitTesting(onHome)
      // The menu bar window doesn't follow content height changes, so the detail page
      // overlays a fixed-height home page instead of growing it.
      .frame(width: 320)
      .frame(minHeight: 380, alignment: .top)
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
          .padding(.top, 10)
          .transition(.move(edge: .trailing).combined(with: .opacity))
        } else if inviting {
          InviteView(back: { go { inviting = false } })
            .padding(.vertical, 10)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        } else if awaySettings {
          AwaySettingsView(back: { go { awaySettings = false } })
            .padding(.top, 10)
            .transition(.move(edge: .trailing).combined(with: .opacity))
        }
      }
      .clipped()
      .font(Typography.body)
      .background(popoverBackground.ignoresSafeArea())
      .task { await store.autoRefresh() }
      .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
        Task { await store.refresh() }
      }
      .onChange(of: store.settingKey) { _ in store.scheduleSave() }
  }

  private var home: some View {
    VStack(alignment: .leading, spacing: 0) {
      header
      if let problem = store.online ? store.saveError : store.statusLine {
        Notice(text: problem).padding(.horizontal, inset).padding(.top, 8)
      }
      lendingStatus
        .padding(.horizontal, inset)
        .padding(.top, 12)
      SectionHeader(title: "This week")
        .padding(.top, 12)
      HStack(spacing: 8) {
        WeekTile(title: "Lent", icon: "arrow.up.right", value: store.borrowedWeekTotal)
        WeekTile(title: "Borrowed", icon: "arrow.down.left", value: store.borrowedByMeWeekTotal)
      }
      .padding(.horizontal, inset)
      if !store.lendingMembers.isEmpty || store.canInvite {
        MenuSeparator().padding(.top, 4)
        SectionHeader(title: "People")
        ForEach(store.lendingMembers) { member in
          PersonRow(member: member, source: store.borrowSources.first { $0.name == member.name }) {
            withAnimation(.easeInOut(duration: 0.2)) { selected = member.name }
          }
        }
        if store.canInvite {
          HoverRow(action: { withAnimation(.easeInOut(duration: 0.2)) { inviting = true } }) {
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
      if !store.subscriptionConnected {
        MenuSeparator()
        HoverRow(action: { store.runConnect() }) {
          Text(store.connectHint ?? "Connect Subscription…")
        }
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
      .padding(10)
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
        Text("lembas").font(Typography.title)
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
        if let me = store.me { Text("Signed in as \(prettyName(me))") }
        Button(store.subscriptionConnected ? "Reconnect Subscription…" : "Connect Subscription…") { store.runConnect() }
        Divider()
        Button("Quit lembas") { NSApp.terminate(nil) }
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
    return who + (store.routedThroughPool ? "Fallback on" : "Fallback off")
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

@main
struct PoolBarApp: App {
  @StateObject private var store = Store()
  var body: some Scene {
    MenuBarExtra {
      if store.config == nil { SetupView().environmentObject(store) }
      else { MainView().environmentObject(store) }
    } label: {
      Image(nsImage: LembasLogo.menuBar)
        .accessibilityLabel("lembas")
    }
    .menuBarExtraStyle(.window)
  }
}
