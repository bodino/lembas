// The lembas logo, drawn in code: a parcel of waybread wrapped in green leaves and
// tied with twine. The detailed illustration is for large icon sizes; small sizes
// (in-app badge, login page, 16–32 px icons, menu bar) use the simplified glyph — the
// parcel's silhouette with the twine knocked out — so it stays readable.

import AppKit

enum LembasLogo {
  // Small full-color tile (green squircle, cream glyph), filling `size` edge to edge.
  static func tile(size: CGFloat) -> NSImage {
    NSImage(size: NSSize(width: size, height: size), flipped: false) { rect in
      guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
      drawSmallTile(ctx, in: rect)
      return true
    }
  }

  // App icon artwork on Apple's 1024 grid: an 824 tile centered, with its drop shadow.
  static func appIconPNG(pixels: Int) -> Data? {
    render(pixels: pixels) { ctx, side in
      let tile = CGRect(x: side * 100 / 1024, y: side * 100 / 1024, width: side * 824 / 1024, height: side * 824 / 1024)
      ctx.saveGState()
      ctx.setShadow(offset: CGSize(width: 0, height: -side * 0.012), blur: side * 0.03,
                    color: CGColor(gray: 0, alpha: 0.3))
      ctx.addPath(squircle(tile))
      ctx.setFillColor(rgb(0xF3E9D6))
      ctx.fillPath()
      ctx.restoreGState()
      if pixels <= 64 { drawSmallTile(ctx, in: tile) } else { drawTile(ctx, in: tile) }
    }
  }

  // The tile as PNG, for places that need image data (the login page).
  static func tilePNG(pixels: Int) -> Data? {
    render(pixels: pixels) { ctx, side in drawSmallTile(ctx, in: CGRect(x: 0, y: 0, width: side, height: side)) }
  }

  // Menu bar template: the parcel's silhouette with the twine knocked out. macOS tints
  // template images for light/dark menu bars, as the HIG asks of menu bar extras.
  static let menuBar: NSImage = {
    let image = NSImage(size: NSSize(width: 18, height: 18), flipped: false) { rect in
      guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
      drawGlyph(ctx, center: CGPoint(x: rect.midX, y: rect.midY), halfSide: 6.2, color: .black)
      return true
    }
    image.isTemplate = true
    return image
  }()

  // ---------- drawing ----------

  // The simplified parcel: a square on its point, twine cross and knot knocked out.
  // Proportions are tuned at menu bar size (half side 6.2 pt) and scale from there.
  private static func drawGlyph(_ ctx: CGContext, center: CGPoint, halfSide: CGFloat, color: CGColor) {
    let k = halfSide / 6.2
    let parcel = Parcel(center: center, halfSide: halfSide, tilt: 0)
    ctx.saveGState()
    ctx.beginTransparencyLayer(auxiliaryInfo: nil)
    ctx.addPath(parcel.outline(cornerRadius: 1.4 * k))
    ctx.setFillColor(color)
    ctx.fillPath()
    ctx.setBlendMode(.clear)
    ctx.setLineCap(.round)
    ctx.setLineWidth(1.3 * k)
    for (from, to) in parcel.twine(overhang: 0) {
      ctx.move(to: from)
      ctx.addLine(to: to)
    }
    ctx.strokePath()
    ctx.fillEllipse(in: CGRect(x: center.x - 2.4 * k, y: center.y - 2.4 * k, width: 4.8 * k, height: 4.8 * k))
    ctx.setBlendMode(.normal)
    ctx.setFillColor(color)
    ctx.fillEllipse(in: CGRect(x: center.x - 1.3 * k, y: center.y - 1.3 * k, width: 2.6 * k, height: 2.6 * k))
    ctx.endTransparencyLayer()
    ctx.restoreGState()
  }

  private static func drawSmallTile(_ ctx: CGContext, in rect: CGRect) {
    let shape = squircle(rect)
    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    let leaf = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                          colors: [rgb(0x3E7349), rgb(0x2A5231)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(leaf, start: CGPoint(x: rect.midX, y: rect.maxY),
                           end: CGPoint(x: rect.midX, y: rect.minY), options: [])
    drawGlyph(ctx, center: CGPoint(x: rect.midX, y: rect.midY), halfSide: rect.width * 0.27, color: rgb(0xF4E8CF))
    ctx.restoreGState()
  }

  private static func drawTile(_ ctx: CGContext, in rect: CGRect) {
    let shape = squircle(rect)
    ctx.saveGState()
    ctx.addPath(shape)
    ctx.clip()
    // Parchment, lit from above.
    let background = CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB),
                                colors: [rgb(0xFBF6EC), rgb(0xEADCC0)] as CFArray, locations: [0, 1])!
    ctx.drawLinearGradient(background, start: CGPoint(x: rect.midX, y: rect.maxY),
                           end: CGPoint(x: rect.midX, y: rect.minY), options: [])
    drawParcel(ctx, center: CGPoint(x: rect.midX, y: rect.midY + rect.height * 0.01), unit: rect.width / 100)
    ctx.restoreGState()
    // Hairline edge so the tile holds up on light backgrounds.
    ctx.addPath(shape)
    ctx.setStrokeColor(CGColor(gray: 0, alpha: 0.08))
    ctx.setLineWidth(max(rect.width / 200, 0.5))
    ctx.strokePath()
  }

  private static func drawParcel(_ ctx: CGContext, center: CGPoint, unit u: CGFloat) {
    let parcel = Parcel(center: center, halfSide: 27 * u, tilt: -0.1)
    let corners = parcel.corners

    // Bread, with a soft shadow under the whole parcel.
    ctx.saveGState()
    ctx.setShadow(offset: CGSize(width: 0, height: -1.6 * u), blur: 4 * u, color: CGColor(gray: 0, alpha: 0.28))
    ctx.addPath(parcel.outline(cornerRadius: 3 * u))
    ctx.setFillColor(rgb(0xE9D2A6))
    ctx.fillPath()
    ctx.restoreGState()
    ctx.addPath(parcel.outline(cornerRadius: 3 * u))
    ctx.setStrokeColor(rgb(0xC4A06C))
    ctx.setLineWidth(0.6 * u)
    ctx.strokePath()

    // Four leaves folded in like a pinwheel, each reaching past the center so they
    // overlap; the bread only shows at the corner tips.
    let greens = [0x2F5C38, 0x3A6D44, 0x2A5231, 0x356440]
    ctx.setLineJoin(.round)
    for i in 0..<4 {
      let a = corners[i], b = corners[(i + 1) % 4]
      let start = lerp(a, b, 0.13)
      let end = lerp(b, a, 0.13)
      let side = lerp(a, b, 0.5)
      // Past the center, nudged toward the next corner for the pinwheel overlap.
      let apex = CGPoint(x: center.x + (center.x - side.x) * 0.28 + (b.x - center.x) * 0.12,
                         y: center.y + (center.y - side.y) * 0.28 + (b.y - center.y) * 0.12)
      let leaf = CGMutablePath()
      let middle = CGPoint(x: (start.x + end.x + apex.x) / 3, y: (start.y + end.y + apex.y) / 3)
      leaf.move(to: start)
      leaf.addQuadCurve(to: end, control: bulge(start, end, away: middle, by: 1.2 * u))
      leaf.addQuadCurve(to: apex, control: bulge(end, apex, away: middle, by: 2.2 * u))
      leaf.addQuadCurve(to: start, control: bulge(apex, start, away: middle, by: 1.6 * u))
      leaf.closeSubpath()
      ctx.addPath(leaf)
      ctx.setFillColor(rgb(greens[i]))
      ctx.fillPath()
      // Midrib.
      ctx.move(to: lerp(lerp(start, end, 0.5), apex, 0.08))
      ctx.addLine(to: lerp(lerp(start, end, 0.5), apex, 0.7))
      ctx.setStrokeColor(CGColor(srgbRed: 0.42, green: 0.62, blue: 0.45, alpha: 0.55))
      ctx.setLineWidth(0.5 * u)
      ctx.strokePath()
      ctx.addPath(leaf)
      ctx.setStrokeColor(rgb(0x1C3922))
      ctx.setLineWidth(0.7 * u)
      ctx.strokePath()
    }

    // Twine: a darker edge under a lighter strand, crossing at the knot.
    ctx.setLineCap(.round)
    for (width, color) in [(2.2 * u, rgb(0x7E5B2C)), (1.4 * u, rgb(0xC9994F))] {
      for (from, to) in parcel.twine(overhang: 0.03) {
        ctx.move(to: from)
        ctx.addLine(to: to)
      }
      ctx.setStrokeColor(color)
      ctx.setLineWidth(width)
      ctx.strokePath()
    }
    // The knot: a bow of two loops and short tails.
    let knot = CGPoint(x: center.x + 0.6 * u, y: center.y + 0.6 * u)
    ctx.setStrokeColor(rgb(0xC9994F))
    ctx.setLineWidth(1.4 * u)
    for angle in [CGFloat.pi * 0.2, CGFloat.pi * 1.2] {
      ctx.saveGState()
      ctx.translateBy(x: knot.x, y: knot.y)
      ctx.rotate(by: angle)
      ctx.strokeEllipse(in: CGRect(x: 0, y: -2 * u, width: 7.5 * u, height: 4 * u))
      ctx.restoreGState()
    }
    ctx.move(to: knot)
    ctx.addQuadCurve(to: CGPoint(x: knot.x + 2 * u, y: knot.y - 6 * u), control: CGPoint(x: knot.x + 3 * u, y: knot.y - 2 * u))
    ctx.move(to: knot)
    ctx.addQuadCurve(to: CGPoint(x: knot.x - 5 * u, y: knot.y - 4 * u), control: CGPoint(x: knot.x - 2 * u, y: knot.y - 3.5 * u))
    ctx.strokePath()
    ctx.setFillColor(rgb(0x9C7238))
    ctx.fillEllipse(in: CGRect(x: knot.x - 2 * u, y: knot.y - 2 * u, width: 4 * u, height: 4 * u))
  }

  // ---------- geometry ----------

  // A square set on its point (rotated 45°, plus a little tilt).
  private struct Parcel {
    let center: CGPoint
    let halfSide: CGFloat
    let tilt: CGFloat

    var corners: [CGPoint] {
      let h = halfSide
      let angle: CGFloat = .pi / 4 + tilt
      let cosA = cos(angle), sinA = sin(angle)
      let unit: [(CGFloat, CGFloat)] = [(-1, -1), (1, -1), (1, 1), (-1, 1)]
      return unit.map { pair -> CGPoint in
        let x = pair.0 * h, y = pair.1 * h
        return CGPoint(x: center.x + x * cosA - y * sinA, y: center.y + x * sinA + y * cosA)
      }
    }

    func outline(cornerRadius: CGFloat) -> CGPath {
      let c = corners
      let path = CGMutablePath()
      path.move(to: lerp(c[0], c[1], 0.5))
      for i in 1...4 {
        path.addArc(tangent1End: c[i % 4], tangent2End: c[(i + 1) % 4], radius: cornerRadius)
      }
      path.closeSubpath()
      return path
    }

    // Two strands through the center, parallel to the parcel's sides.
    func twine(overhang: CGFloat) -> [(CGPoint, CGPoint)] {
      let c = corners
      let pairs = [(lerp(c[0], c[1], 0.5), lerp(c[2], c[3], 0.5)), (lerp(c[1], c[2], 0.5), lerp(c[3], c[0], 0.5))]
      return pairs.map { a, b in (lerp(a, b, -overhang), lerp(a, b, 1 + overhang)) }
    }
  }

  // Apple's icon corner ratio (185 of 824), drawn as a continuous-looking rounded rect.
  private static func squircle(_ rect: CGRect) -> CGPath {
    CGPath(roundedRect: rect, cornerWidth: rect.width * 0.2247, cornerHeight: rect.width * 0.2247, transform: nil)
  }

  private static func lerp(_ a: CGPoint, _ b: CGPoint, _ t: CGFloat) -> CGPoint {
    CGPoint(x: a.x + (b.x - a.x) * t, y: a.y + (b.y - a.y) * t)
  }

  // Control point that bows the segment a→b outward, away from `inside`.
  private static func bulge(_ a: CGPoint, _ b: CGPoint, away inside: CGPoint, by amount: CGFloat) -> CGPoint {
    let mid = lerp(a, b, 0.5)
    let dx = b.x - a.x, dy = b.y - a.y
    let length = max(hypot(dx, dy), 0.001)
    var normal = CGPoint(x: -dy / length, y: dx / length)
    if (mid.x - inside.x) * normal.x + (mid.y - inside.y) * normal.y < 0 { normal = CGPoint(x: -normal.x, y: -normal.y) }
    return CGPoint(x: mid.x + normal.x * amount, y: mid.y + normal.y * amount)
  }

  private static func rgb(_ hex: Int) -> CGColor {
    CGColor(srgbRed: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
  }

  private static func render(pixels: Int, _ draw: (CGContext, CGFloat) -> Void) -> Data? {
    guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: pixels, pixelsHigh: pixels,
                                     bitsPerSample: 8, samplesPerPixel: 4, hasAlpha: true, isPlanar: false,
                                     colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0),
          let context = NSGraphicsContext(bitmapImageRep: rep) else { return nil }
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = context
    draw(context.cgContext, CGFloat(pixels))
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])
  }
}
