#!/bin/sh
# Put the release build into a folder and pack it:
#
#     scripts/package-linux.sh <target triple> <version> <label>
#
# The package is a plain tar.gz: unpack it anywhere and run `wisp-ops`.
set -eu
target=$1
version=$2
label=$3
release="target/$target/release"
name="WispOps-v$version-$label"

rm -rf "dist/$name"
mkdir -p "dist/$name"
cp "$release/wisp_ops" "dist/$name/wisp-ops"
cp assets/branding/app-icon.png "dist/$name/wisp-ops.png"
cp LICENSE THIRD_PARTY.md README.md "dist/$name/"

# For a launcher entry: copy it to ~/.local/share/applications and point Exec and Icon at this folder.
cat > "dist/$name/wisp-ops.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=WispOps
Comment=AI 原生的服务器运维桌面工具
Exec=wisp-ops
Icon=wisp-ops
Categories=System;Network;
StartupWMClass=com.wisp.ops
DESKTOP

tar -C dist -czf "dist/$name.tar.gz" "$name"
echo "dist/$name.tar.gz"
