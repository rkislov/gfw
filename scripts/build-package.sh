#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
gfw_arch=${GFW_PACKAGE_ARCH:-$(go env GOARCH)}
gfw_version=${GFW_PACKAGE_VERSION:-0.22.4}
gfw_target=${1:-altp10}
case "$gfw_version" in ''|*[!a-zA-Z0-9.+~-]*) echo 'Invalid package version' >&2; exit 1;; esac
case "$gfw_arch" in
    arm64) gfw_rpm_arch=aarch64 ;;
    amd64) gfw_rpm_arch=x86_64 ;;
    *) echo 'Use GFW_PACKAGE_ARCH=amd64 or arm64' >&2; exit 1 ;;
esac
case "$gfw_target" in
    altp10|altp11)
        gfw_format=rpm
        gfw_release=1.$gfw_target
        gfw_filename=gfw-$gfw_version-$gfw_release.$gfw_rpm_arch.rpm
        gfw_dependencies='[systemd, nftables, etcnet, iproute2, shadow-utils, openssl, "openvpn >= 2.6", "strongswan >= 5.9.13", "suricata >= 8.0.4", tcpdump]'
        ;;
    ubuntu26.04)
        gfw_format=deb
        gfw_release=1.ubuntu26.04
        gfw_filename=gfw_${gfw_version}-${gfw_release}_${gfw_arch}.deb
        gfw_dependencies='[systemd, dbus, "netplan.io (>= 1.2)", nftables, iproute2, passwd, openssl, ca-certificates, "openvpn (>= 2.6)", "strongswan-charon (>= 5.9.13)", strongswan-swanctl, libcharon-extra-plugins, libstrongswan-extra-plugins, "suricata (>= 1:8.0.3)", tcpdump]'
        ;;
    *) echo 'Use altp10, altp11 or ubuntu26.04' >&2; exit 1 ;;
esac
gfw_nfpm=${GFW_NFPM:-nfpm}
if ! command -v "$gfw_nfpm" >/dev/null 2>&1; then
    echo 'Install nfpm or set GFW_NFPM to its absolute path' >&2
    exit 1
fi
gfw_stage=$(mktemp -d /tmp/gfw-package.XXXXXX)
trap 'rm -rf "$gfw_stage"' EXIT
trap 'exit 1' HUP INT TERM
gfw_unit=./deploy/systemd/gfw-agent.service
case "$gfw_target" in
    altp11)
        gfw_unit=$gfw_stage/gfw-agent.service
        sed 's@ -nft /usr/sbin/nft @ -nft /usr/sbin/nft -charon /usr/libexec/strongswan/charon @' \
            deploy/systemd/gfw-agent.service > "$gfw_unit"
        ;;
    ubuntu26.04)
        gfw_unit=$gfw_stage/gfw-agent.service
        sed 's/^Wants=network-online.target$/Wants=network-online.target dbus.socket/; s/^After=network-online.target /After=network-online.target systemd-networkd.service dbus.socket /; s/ -enable-network / -enable-network -network-backend netplan /; s@ /etc/net/ifaces@ /etc/netplan@; s@ -nft /usr/sbin/nft @ -nft /usr/sbin/nft -ip /usr/sbin/ip -charon /usr/lib/ipsec/charon @' \
            deploy/systemd/gfw-agent.service > "$gfw_unit"
        ;;
esac
mkdir -p dist "bin/linux-$gfw_arch"
for gfw_command in gfwd gfw-agent; do
    CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath \
        -ldflags "-X github.com/rkislov/gfw/internal/server.version=$gfw_version" \
        -o "$gfw_stage/$gfw_command" "./cmd/$gfw_command"
done
mkdir "$gfw_stage/go-licenses"
gfw_go_root=$(go env GOROOT)
cp "$gfw_go_root/LICENSE" "$gfw_go_root/PATENTS" "$gfw_stage/go-licenses/"
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go list -deps \
    -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{"\t"}}{{.Dir}}{{end}}{{end}}' \
    ./cmd/gfwd ./cmd/gfw-agent > "$gfw_stage/go-modules"
LC_ALL=C sort -u "$gfw_stage/go-modules" > "$gfw_stage/go-modules-unique"
while IFS="$(printf '\t')" read -r gfw_module gfw_module_dir; do
    [ -n "$gfw_module" ] || continue
    gfw_license_dir=$gfw_stage/go-licenses/$gfw_module
    mkdir -p "$gfw_license_dir"
    for gfw_license in "$gfw_module_dir"/LICENSE* "$gfw_module_dir"/license* \
        "$gfw_module_dir"/LICENCE* "$gfw_module_dir"/NOTICE* "$gfw_module_dir"/COPYING* \
        "$gfw_module_dir"/COPYRIGHT* "$gfw_module_dir"/PATENTS*; do
        if [ -f "$gfw_license" ]; then cp "$gfw_license" "$gfw_license_dir/"; fi
    done
    if [ -z "$(ls -A "$gfw_license_dir")" ]; then
        printf 'Missing dependency license: %s\n' "$gfw_module" >&2
        exit 1
    fi
done < "$gfw_stage/go-modules-unique"
sed -e "s/__GFW_ARCH__/$gfw_arch/g" \
    -e "s/__GFW_VERSION__/$gfw_version/g" \
    -e "s/__GFW_RELEASE__/$gfw_release/g" \
    -e "s|__GFW_AGENT_UNIT__|$gfw_unit|g" \
    -e "s|__GFW_BIN_DIR__|$gfw_stage|g" \
    -e "s|__GFW_DEPENDENCIES__|$gfw_dependencies|g" \
    deploy/package/nfpm.yaml > "$gfw_stage/nfpm.yaml"
"$gfw_nfpm" package --packager "$gfw_format" --config "$gfw_stage/nfpm.yaml" --target "$gfw_stage/$gfw_filename"
mv "$gfw_stage/gfwd" "$gfw_stage/gfw-agent" "bin/linux-$gfw_arch/"
mv "$gfw_stage/$gfw_filename" "dist/$gfw_filename"
printf '%s\n' "dist/$gfw_filename"
