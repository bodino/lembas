// Writes the app icon set from src/Logo.swift, plus the small logo the pool's invite
// page shows. Usage: make-icon <out.iconset> <logo.png>
import AppKit

@main
struct MakeIcon {
  static func main() throws {
    let out = URL(fileURLWithPath: CommandLine.arguments[1])
    try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)
    for points in [16, 32, 128, 256, 512] {
      for scale in [1, 2] {
        let name = "icon_\(points)x\(points)\(scale == 2 ? "@2x" : "").png"
        try LembasLogo.appIconPNG(pixels: points * scale)!.write(to: out.appendingPathComponent(name))
      }
    }
    try LembasLogo.tilePNG(pixels: 88)!.write(to: URL(fileURLWithPath: CommandLine.arguments[2]))
  }
}
