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

# The MPC-TLS helper for private borrowing (docs/mpc-tls.md): TLSNotary at a pinned
# commit plus our patch, with our crate copied in, built for both architectures. Needs
# Rust via rustup (the fork pins its toolchain; the targets are added here). It lands in
# the app for members' agents and in build/ for the pool. LEMBAS_SKIP_MPC=1 builds the
# app without it, for quick local work: such a build can't borrow privately.
TLSN_COMMIT=eb19c82
if [ -z "$LEMBAS_SKIP_MPC" ]; then
  command -v cargo >/dev/null 2>&1 || { echo "lembas needs Rust (https://rustup.rs) for the MPC helper; LEMBAS_SKIP_MPC=1 builds without it." >&2; exit 1; }
  [ -d build/tlsn/.git ] || git clone -q https://github.com/tlsnotary/tlsn build/tlsn
  (cd build/tlsn && git checkout -q --detach "$TLSN_COMMIT" 2>/dev/null || { git fetch -q origin "$TLSN_COMMIT" && git checkout -q --detach "$TLSN_COMMIT"; }
   git reset -q --hard && git clean -qfd && git apply "../../mpc-tls/tlsn-$TLSN_COMMIT-lembas-splice.patch")
  rm -rf build/tlsn/crates/lembas-mpc
  cp -R mpc-tls/lembas-mpc build/tlsn/crates/lembas-mpc
  TOOLCHAIN=$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' build/tlsn/rust-toolchain.toml)
  for target in aarch64-apple-darwin x86_64-apple-darwin; do
    rustup target add --toolchain "$TOOLCHAIN" $target >/dev/null 2>&1 || rustup toolchain install "$TOOLCHAIN" --profile minimal --target $target
    (cd build/tlsn && cargo build -q --release -p lembas-mpc --bin lembas-mpc --target $target)
  done
  lipo -create build/tlsn/target/aarch64-apple-darwin/release/lembas-mpc build/tlsn/target/x86_64-apple-darwin/release/lembas-mpc -output build/lembas-mpc
  cp build/lembas-mpc "$APP/MacOS/lembas-mpc"
  echo "built lembas-mpc (tlsn $TLSN_COMMIT + patch, $TOOLCHAIN)"
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
# Members' apps read this from the latest GitHub release and offer the update.
SHA=$(shasum -a 256 installer/lembas.zip | cut -d' ' -f1)
printf '{"version": "%s", "build": %s, "sha256": "%s"}\n' "$VERSION" "$BUILD" "$SHA" > installer/version.json
echo "built lembas $VERSION ($BUILD): build/lembas.app, installer/lembas.zip, installer/version.json"
