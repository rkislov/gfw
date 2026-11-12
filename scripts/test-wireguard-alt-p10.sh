#!/bin/sh
set -eu
gfw_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$gfw_root"
gfw_arch=${GFW_LAB_ARCH:-$(go env GOARCH)}
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go build -trimpath -o "bin/linux-$gfw_arch/gfw-agent" ./cmd/gfw-agent
docker build --platform "linux/$gfw_arch" -t "gfw-alt-p10-lab:$gfw_arch" -f deploy/lab/Dockerfile .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_LAB_BASE=gfw-alt-p10-lab:$gfw_arch" -t "gfw-alt-p10-package-lab:$gfw_arch" -f deploy/lab/Dockerfile.package .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_WG_LAB_BASE=gfw-alt-p10-package-lab:$gfw_arch" -t "gfw-alt-p10-wireguard-lab:$gfw_arch" -f deploy/lab/Dockerfile.wireguard .
CGO_ENABLED=0 GOOS=linux GOARCH="$gfw_arch" go test -c -o "bin/linux-$gfw_arch/wireguard.test" ./internal/wireguard
docker run --rm --platform "linux/$gfw_arch" --privileged --network none -e GFW_WG_KERNEL_TEST=1 --mount "type=bind,source=$gfw_root,target=/work,readonly" "gfw-alt-p10-wireguard-lab:$gfw_arch" "/work/bin/linux-$gfw_arch/wireguard.test"
docker run --rm --platform "linux/$gfw_arch" --privileged --network none --mount "type=bind,source=$gfw_root,target=/work,readonly" --tmpfs /state:mode=0700 "gfw-alt-p10-wireguard-lab:$gfw_arch" python3 /work/scripts/wireguard-lab.py
