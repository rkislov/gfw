#!/bin/sh
set -eu
gfw_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$gfw_root"
gfw_arch=${GFW_PACKAGE_ARCH:-$(go env GOARCH)}
case "$gfw_arch" in arm64|amd64) ;; *) exit 1;; esac
mkdir -p "bin/linux-$gfw_arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath -o "bin/linux-$gfw_arch/gfwd" ./cmd/gfwd
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath -o "bin/linux-$gfw_arch/gfw-agent" ./cmd/gfw-agent
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go test -c -o "bin/linux-$gfw_arch/pki-openvpn.test" ./internal/pki
docker build --platform "linux/$gfw_arch" -t "gfw-alt-p10-lab:$gfw_arch" -f deploy/lab/Dockerfile .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_LAB_BASE=gfw-alt-p10-lab:$gfw_arch" -t "gfw-alt-p10-package-lab:$gfw_arch" -f deploy/lab/Dockerfile.package .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_LAB_BASE=gfw-alt-p10-package-lab:$gfw_arch" -t "gfw-alt-p10-openvpn-lab:$gfw_arch" -f deploy/lab/Dockerfile.openvpn .
docker run --rm --platform "linux/$gfw_arch" --privileged --network none \
 --mount "type=bind,source=$gfw_root,target=/work,readonly" --tmpfs /state:mode=0700 \
 -e TMPDIR=/state -e GFW_OPENVPN_LAB=1 "gfw-alt-p10-openvpn-lab:$gfw_arch" \
 "/work/bin/linux-$gfw_arch/pki-openvpn.test" -test.v -test.run '^TestOpenVPNRealClientProfile$' -test.timeout 90s

docker run --rm --platform "linux/$gfw_arch" --privileged --network none \
 --mount "type=bind,source=$gfw_root,target=/work,readonly" --tmpfs /state:mode=0700 --tmpfs /run/ovpn:mode=0700 \
 "gfw-alt-p10-openvpn-lab:$gfw_arch" python3 /work/scripts/openvpn-agent-lab.py
