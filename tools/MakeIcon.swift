// Writes the app icon set from src/Logo.swift. Usage: make-icon <out.iconset>
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
  }
}
