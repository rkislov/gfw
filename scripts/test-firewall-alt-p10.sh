#!/bin/sh
set -eu
task_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$task_root"
lab_arch=${GFW_LAB_ARCH:-$(go env GOARCH)}
case "$lab_arch" in arm64|amd64) ;; *) echo 'Set GFW_LAB_ARCH=arm64 or amd64' >&2; exit 1;; esac
CGO_ENABLED=0 GOOS=linux GOARCH="$lab_arch" go build -trimpath -o "bin/linux-$lab_arch/gfw-agent" ./cmd/gfw-agent
docker build --platform "linux/$lab_arch" -t "gfw-alt-p10-lab:$lab_arch" -f deploy/lab/Dockerfile .
docker run --rm --platform "linux/$lab_arch" --privileged --network none \
 --mount "type=bind,source=$task_root,target=/work,readonly" --tmpfs /state:mode=0700 \
 "gfw-alt-p10-lab:$lab_arch" python3 /work/scripts/firewall-lab.py
