#!/usr/bin/env bash
# Builds, tests and packages the native SwiftUI app as a universal (Apple Silicon +
# Intel) .app bundle, then writes a ZIP and its SHA-256 sidecar to ../artifacts.
#
#   ./macos-native/package.sh [version]
set -euo pipefail

package_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repository_root="$(cd "$package_root/.." && pwd)"

if [[ $# -ge 1 ]]; then
  version="$1"
else
  version="$(sed -n 's:.*<VersionPrefix>\(.*\)</VersionPrefix>.*:\1:p' "$repository_root/Directory.Build.props")"
fi
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  printf 'Version "%s" is not a supported semantic version.\n' "$version" >&2
  exit 1
fi
bundle_version="${version%%-*}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  printf 'The native macOS app can only be built on macOS with Xcode or the Command Line Tools.\n' >&2
  exit 1
fi

artifacts_root="$repository_root/artifacts"
app_bundle="$artifacts_root/native/SSH Key Deployer.app"
archive_name="SSH-Key-Deployer-v${version}-macos-universal.zip"
archive_path="$artifacts_root/$archive_name"
checksum_path="$archive_path.sha256"

cd "$package_root"
swift test
swift build --configuration release --arch arm64 --arch x86_64
binary="$(swift build --configuration release --arch arm64 --arch x86_64 --show-bin-path)/SSHKeyDeployer"

rm -rf -- "$app_bundle"
rm -f -- "$archive_path" "$checksum_path"
mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources"
cp "$binary" "$app_bundle/Contents/MacOS/SSHKeyDeployer"
sed "s/@VERSION@/$bundle_version/g" "$package_root/Info.plist.template" > "$app_bundle/Contents/Info.plist"
plutil -lint "$app_bundle/Contents/Info.plist" >/dev/null

architectures="$(lipo -archs "$app_bundle/Contents/MacOS/SSHKeyDeployer")"
for arch in arm64 x86_64; do
  if [[ " $architectures " != *" $arch "* ]]; then
    printf 'The app binary is missing the %s slice (found: %s).\n' "$arch" "$architectures" >&2
    exit 1
  fi
done

# Ad-hoc signature: required for Apple Silicon to launch the binary at all. It is not
# a Developer ID signature, so Gatekeeper still asks for confirmation on first launch.
codesign --force --deep --sign - "$app_bundle"
codesign --verify --strict "$app_bundle"

ditto -c -k --sequesterRsrc --keepParent "$app_bundle" "$archive_path"
(cd "$artifacts_root" && shasum -a 256 "$archive_name") > "$checksum_path"

printf 'Release archive: %s\n' "$archive_path"
printf 'SHA-256 file:   %s\n' "$checksum_path"
