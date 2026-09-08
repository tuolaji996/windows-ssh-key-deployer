#!/usr/bin/env bash
set -euo pipefail

version="${1:-1.2.1}"
configuration="${2:-Release}"
bundle_version="${version%%-*}"
repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet_bin="${DOTNET_BIN:-dotnet}"
mac_project="$repository_root/src/SshKeyDeployer.Mac/SshKeyDeployer.Mac.csproj"
self_test_project="$repository_root/tests/SshKeyDeployer.SelfTest/SshKeyDeployer.SelfTest.csproj"
artifacts_root="$repository_root/artifacts"
publish_directory="$artifacts_root/publish-osx-arm64"
app_bundle="$artifacts_root/SSH Key Deployer.app"
archive_name="SSH-Key-Deployer-v${version}-osx-arm64.zip"
archive_path="$artifacts_root/$archive_name"
checksum_path="$archive_path.sha256"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z]+([.-][0-9A-Za-z]+)*)?$ ]]; then
  printf 'Version %s is not a supported semantic version.\n' "$version" >&2
  exit 1
fi

if ! command -v "$dotnet_bin" >/dev/null 2>&1; then
  printf '.NET 8 SDK was not found. Set DOTNET_BIN or install .NET 8.\n' >&2
  exit 1
fi

"$dotnet_bin" build "$repository_root/src/SshKeyDeployer.Core/SshKeyDeployer.Core.csproj" \
  --configuration "$configuration" --nologo -warnaserror
"$dotnet_bin" build "$mac_project" --configuration "$configuration" --nologo -warnaserror
"$dotnet_bin" build "$self_test_project" --configuration "$configuration" --nologo -warnaserror
"$dotnet_bin" run --project "$self_test_project" --configuration "$configuration" --no-build --no-restore

mkdir -p "$artifacts_root"
rm -rf -- "$publish_directory" "$app_bundle"
rm -f -- "$archive_path" "$checksum_path"

"$dotnet_bin" publish "$mac_project" \
  --configuration "$configuration" \
  --runtime osx-arm64 \
  --self-contained true \
  --output "$publish_directory" \
  --nologo \
  -p:UseAppHost=true \
  -p:PublishSingleFile=false \
  -p:PublishTrimmed=false \
  -p:DebugType=None \
  -p:DebugSymbols=false \
  -p:Version="$version"

mkdir -p "$app_bundle/Contents/MacOS" "$app_bundle/Contents/Resources"
cp -R "$publish_directory/." "$app_bundle/Contents/MacOS/"
sed "s/@VERSION@/$bundle_version/g" "$repository_root/src/SshKeyDeployer.Mac/Info.plist.template" \
  > "$app_bundle/Contents/Info.plist"

executable_path="$app_bundle/Contents/MacOS/SshKeyDeployer"
if [[ ! -f "$executable_path" ]]; then
  printf 'Expected macOS app executable was not produced: %s\n' "$executable_path" >&2
  exit 1
fi
chmod u+x "$executable_path"

if command -v file >/dev/null 2>&1; then
  file_output="$(file "$executable_path")"
  printf '%s\n' "$file_output"
  if [[ "$file_output" != *"arm64"* && "$file_output" != *"arm 64"* ]]; then
    printf 'The bundled executable is not reported as arm64.\n' >&2
    exit 1
  fi
fi

if command -v ditto >/dev/null 2>&1; then
  ditto -c -k --sequesterRsrc --keepParent "$app_bundle" "$archive_path"
elif command -v zip >/dev/null 2>&1; then
  (
    cd "$artifacts_root"
    zip -qr "$archive_name" "$(basename "$app_bundle")"
  )
else
  printf 'macOS ditto or a zip-compatible archiver is required to create the release archive.\n' >&2
  exit 1
fi

if ! unzip -Z1 "$archive_path" | grep -Fqx "SSH Key Deployer.app/Contents/MacOS/SshKeyDeployer"; then
  printf 'The archive does not contain the macOS application executable.\n' >&2
  exit 1
fi

if command -v shasum >/dev/null 2>&1; then
  hash="$(shasum -a 256 "$archive_path" | awk '{print $1}')"
else
  hash="$(sha256sum "$archive_path" | awk '{print $1}')"
fi
printf '%s  %s\n' "$hash" "$archive_name" > "$checksum_path"

printf 'Release archive: %s\n' "$archive_path"
printf 'SHA-256 file:   %s\n' "$checksum_path"
