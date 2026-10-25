#!/bin/sh
# Builds lembas.app (menu bar app + bundled agent, universal arm64 + x86_64) and
# installer/lembas.zip, which the pool serves at /lembas.zip and releases attach.
set -e
cd "$(dirname "$0")"
APP=build/lembas.app/Contents
TMP=$(mktemp -d)
rm -rf build/lembas.app
mkdir -p "$APP/MacOS" "$APP/Resources"
cp resources/Info.plist "$APP/Info.plist"

for arch in arm64 x86_64; do
  swiftc -parse-as-library -O -target $arch-apple-macos13.0 src/PoolBar.swift src/Login.swift src/Logo.swift src/HTTPServer.swift -o "$TMP/lembas-$arch"
  swiftc -parse-as-library -O -target $arch-apple-macos13.0 src/Agent.swift src/HTTPServer.swift -o "$TMP/lembas-agent-$arch"
done
lipo -create "$TMP/lembas-arm64" "$TMP/lembas-x86_64" -output "$APP/MacOS/lembas"
lipo -create "$TMP/lembas-agent-arm64" "$TMP/lembas-agent-x86_64" -output "$APP/MacOS/lembas-agent"

# App icon, drawn by src/Logo.swift.
swiftc -parse-as-library -O src/Logo.swift tools/MakeIcon.swift -o "$TMP/make-icon"
"$TMP/make-icon" "$TMP/AppIcon.iconset"
iconutil -c icns "$TMP/AppIcon.iconset" -o "$APP/Resources/AppIcon.icns"
rm -rf "$TMP"

# Ad-hoc signature (not notarized): first launch needs System Settings › Open Anyway.
codesign --force -s - "$APP/MacOS/lembas-agent"
codesign --force -s - build/lembas.app
rm -f installer/lembas.zip
(cd build && zip -qry ../installer/lembas.zip lembas.app)
echo "built build/lembas.app and installer/lembas.zip"
