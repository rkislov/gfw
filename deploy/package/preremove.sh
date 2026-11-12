#!/bin/sh
set -eu
# RPM uses 0 on removal, dpkg uses "remove". Preserve services on upgrade.
case "${1:-0}" in
    0|remove)
        if [ -d /run/systemd/system ]; then
            systemctl disable --now gfwd.service gfw-agent.service || true
        fi
        ;;
esac
# Configuration, certificate keys, recovery journal and lease databases remain.
