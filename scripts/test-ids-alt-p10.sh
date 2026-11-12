#!/bin/sh
set -eu
gfw_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$gfw_root"
gfw_arch=${GFW_PACKAGE_ARCH:-$(go env GOARCH)}
case "$gfw_arch" in arm64|amd64) ;; *) exit 1;; esac
GFW_PACKAGE_ARCH="$gfw_arch" ./scripts/build-rpm.sh
docker build --platform "linux/$gfw_arch" -t "gfw-alt-p10-lab:$gfw_arch" -f deploy/lab/Dockerfile .
docker build --platform "linux/$gfw_arch" --build-arg "GFW_LAB_BASE=gfw-alt-p10-lab:$gfw_arch" -t "gfw-alt-p10-package-lab:$gfw_arch" -f deploy/lab/Dockerfile.package .
docker run --rm --platform "linux/$gfw_arch" --privileged --network none --tmpfs /state:mode=0700 \
 --mount "type=bind,source=$gfw_root,target=/work,readonly" \
 "gfw-alt-p10-package-lab:$gfw_arch" python3 /work/scripts/ids-lab.py
