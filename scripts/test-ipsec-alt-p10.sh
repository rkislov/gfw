#!/bin/sh
set -eu
gfw_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$gfw_root"
gfw_arch=${GFW_PACKAGE_ARCH:-$(go env GOARCH)}
case "$gfw_arch" in arm64|amd64) ;; *) exit 1;; esac
mkdir -p "bin/linux-$gfw_arch"
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath -o "bin/linux-$gfw_arch/gfwd" ./cmd/gfwd
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath -o "bin/linux-$gfw_arch/gfw-agent" ./cmd/gfw-agent
docker build --platform "linux/$gfw_arch" -t "gfw-alt-p10-lab:$gfw_arch" -f deploy/lab/Dockerfile .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_LAB_BASE=gfw-alt-p10-lab:$gfw_arch" -t "gfw-alt-p10-package-lab:$gfw_arch" -f deploy/lab/Dockerfile.package .
docker run --rm --platform "linux/$gfw_arch" --privileged --network none \
 --mount "type=bind,source=$gfw_root,target=/work,readonly" --tmpfs /state:mode=0700 --tmpfs /run:mode=0755 \
 -e GFW_IPSEC_LAB=1 "gfw-alt-p10-package-lab:$gfw_arch" sh -ec '
  if ! ip link add xfrmprobe type xfrm if_id 999; then
   echo "This lab requires a Linux kernel with CONFIG_XFRM_INTERFACE; use a Linux VM." >&2
   exit 1
  fi
  ip link del xfrmprobe
  python3 /work/scripts/ipsec-agent-lab.py
 '
