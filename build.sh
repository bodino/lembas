#!/bin/sh
# Builds lembas.app (menu bar app + bundled agent, universal arm64 + x86_64) and
# installer/lembas.zip, which the pool serves at /lembas.zip and releases attach.
set -e
cd "$(dirname "$0")"

# lembas targets macOS 26, so it needs an SDK at least that new. Use the active
# toolchain if it qualifies, otherwise /Applications/Xcode.app (without touching
# xcode-select).
sdk_major() { xcrun --show-sdk-version 2>/dev/null | cut -d. -f1; }
if [ "$(sdk_major)" -lt 26 ] 2>/dev/null || [ -z "$(sdk_major)" ]; then
  export DEVELOPER_DIR=/Applications/Xcode.app/Contents/Developer
  if [ ! -d "$DEVELOPER_DIR" ] || [ "$(sdk_major)" -lt 26 ]; then
    echo "lembas needs Xcode with the macOS 26 SDK or newer." >&2
    exit 1
  fi
fi
echo "using $(xcrun swiftc --version 2>/dev/null | head -1 | sed 's/.*\(Swift version [0-9.]*\).*/\1/'), macOS $(xcrun --show-sdk-version) SDK"
APP=build/lembas.app/Contents
TMP=$(mktemp -d)
rm -rf build/lembas.app
mkdir -p "$APP/MacOS" "$APP/Resources"
cp resources/Info.plist "$APP/Info.plist"
# Every build gets a higher build number, so members' apps see it as an update.
BUILD=$(date -u +%Y%m%d%H%M)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" "$APP/Info.plist"
VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Info.plist")

for arch in arm64 x86_64; do
  xcrun swiftc -parse-as-library -O -target $arch-apple-macos26.0 src/PoolBar.swift src/Login.swift src/Logo.swift src/HTTPServer.swift -o "$TMP/lembas-$arch"
  xcrun swiftc -parse-as-library -O -target $arch-apple-macos26.0 src/Agent.swift src/HTTPServer.swift -o "$TMP/lembas-agent-$arch"
done
lipo -create "$TMP/lembas-arm64" "$TMP/lembas-x86_64" -output "$APP/MacOS/lembas"
lipo -create "$TMP/lembas-agent-arm64" "$TMP/lembas-agent-x86_64" -output "$APP/MacOS/lembas-agent"

# App icon, drawn by src/Logo.swift.
xcrun swiftc -parse-as-library -O src/Logo.swift tools/MakeIcon.swift -o "$TMP/make-icon"
"$TMP/make-icon" "$TMP/AppIcon.iconset" installer/logo.png
iconutil -c icns "$TMP/AppIcon.iconset" -o "$APP/Resources/AppIcon.icns"
rm -rf "$TMP"

# Ad-hoc signature (not notarized): first launch needs System Settings › Open Anyway.
codesign --force -s - "$APP/MacOS/lembas-agent"
codesign --force -s - build/lembas.app
rm -f installer/lembas.zip
(cd build && zip -qry ../installer/lembas.zip lembas.app)
# Members' apps poll this through the pool and offer "Update to …" when it changes.
SHA=$(shasum -a 256 installer/lembas.zip | cut -d' ' -f1)
printf '{"version": "%s", "build": %s, "sha256": "%s"}\n' "$VERSION" "$BUILD" "$SHA" > installer/version.json
echo "built lembas $VERSION ($BUILD): build/lembas.app, installer/lembas.zip, installer/version.json"
