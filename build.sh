#!/bin/sh
# Builds lembas.app (menu bar app + bundled agent, universal arm64 + x86_64) and
# installer/lembas.zip + installer/version.json. Releases are built by
# .github/workflows/release.yml from a version tag; members update only from those.
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

# The helper for private borrowing (docs/mpc-tls.md): the lembas-mpc crate in
# mpc-tls/, a standalone Cargo project on pinned git dependencies (TLSNotary's
# multiplexer and test server, mpz), built for both architectures. Needs Rust via
# rustup (the crate pins its toolchain; the targets are added here). It lands in the
# app for members' agents and in build/ for the pool. LEMBAS_SKIP_MPC=1 builds the app
# without it, for quick local work: such a build can't borrow privately.
if [ -z "$LEMBAS_SKIP_MPC" ]; then
  command -v cargo >/dev/null 2>&1 || { echo "lembas needs Rust (https://rustup.rs) for the MPC helper; LEMBAS_SKIP_MPC=1 builds without it." >&2; exit 1; }
  TOOLCHAIN=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' mpc-tls/lembas-mpc/rust-toolchain.toml)
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add --toolchain "$TOOLCHAIN" $target >/dev/null 2>&1 || rustup toolchain install "$TOOLCHAIN" --profile minimal --target $target
    (cd mpc-tls/lembas-mpc && cargo build -q --release --bin lembas-mpc --target $target)
  done
  lipo -create mpc-tls/lembas-mpc/target/aarch64-apple-darwin/release/lembas-mpc mpc-tls/lembas-mpc/target/x86_64-apple-darwin/release/lembas-mpc -output build/lembas-mpc
  cp build/lembas-mpc "$APP/MacOS/lembas-mpc"
  echo "built lembas-mpc (Rust $TOOLCHAIN)"
fi
# Every build gets a higher build number, so members' apps see it as an update.
BUILD=$(date -u +%Y%m%d%H%M)
/usr/libexec/PlistBuddy -c "Set :CFBundleVersion $BUILD" "$APP/Info.plist"
VERSION=$(/usr/libexec/PlistBuddy -c "Print :CFBundleShortVersionString" "$APP/Info.plist")

for arch in arm64 x86_64; do
  xcrun swiftc -parse-as-library -O -target $arch-apple-macos26.0 src/PoolBar.swift src/Login.swift src/Logo.swift src/HTTPServer.swift -o "$TMP/lembas-$arch"
  xcrun swiftc -parse-as-library -O -target $arch-apple-macos26.0 src/Agent.swift src/HTTPServer.swift src/PrivateBorrow.swift -o "$TMP/lembas-agent-$arch"
done
lipo -create "$TMP/lembas-arm64" "$TMP/lembas-x86_64" -output "$APP/MacOS/lembas"
lipo -create "$TMP/lembas-agent-arm64" "$TMP/lembas-agent-x86_64" -output "$APP/MacOS/lembas-agent"

# App icon, drawn by src/Logo.swift.
xcrun swiftc -parse-as-library -O src/Logo.swift tools/MakeIcon.swift -o "$TMP/make-icon"
"$TMP/make-icon" "$TMP/AppIcon.iconset" installer/logo.png
iconutil -c icns "$TMP/AppIcon.iconset" -o "$APP/Resources/AppIcon.icns"
rm -rf "$TMP"

# Ad-hoc signature (not notarized): first launch needs System Settings › Open Anyway.
[ -f "$APP/MacOS/lembas-mpc" ] && codesign --force -s - "$APP/MacOS/lembas-mpc"
codesign --force -s - "$APP/MacOS/lembas-agent"
codesign --force -s - build/lembas.app
rm -f installer/lembas.zip
(cd build && zip -qry ../installer/lembas.zip lembas.app)
# Members' apps read this from the latest GitHub release and offer the update, but
# only when it carries a signature by the release key (Ed25519; the app pins the
# public half in PoolBar.swift). The release workflow has the private key as a secret
# in LEMBAS_SIGNING_KEY (PEM). A local build without it is unsigned: fine for running
# here, never offered as an update.
SHA=$(shasum -a 256 installer/lembas.zip | cut -d' ' -f1)
SIG=""
if [ -n "$LEMBAS_SIGNING_KEY" ]; then
  # Node signs (its crypto does Ed25519 directly; macOS's LibreSSL can't from the CLI).
  SIG=$(node -e 'const { sign } = require("node:crypto"); process.stdout.write(sign(null, Buffer.from(process.argv[1]), process.env.LEMBAS_SIGNING_KEY).toString("base64"))' "$VERSION $BUILD $SHA")
  [ -n "$SIG" ] || { echo "signing version.json failed" >&2; exit 1; }
  echo "signed version.json with the release key"
fi
printf '{"version": "%s", "build": %s, "sha256": "%s", "signature": "%s"}\n' "$VERSION" "$BUILD" "$SHA" "$SIG" > installer/version.json
echo "built lembas $VERSION ($BUILD): build/lembas.app, installer/lembas.zip, installer/version.json"
