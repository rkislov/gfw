#!/bin/sh
set -eu
getent group gfw >/dev/null 2>&1 || groupadd --system gfw
id gfw >/dev/null 2>&1 || useradd --system -g gfw -d /var/lib/gfw -s /sbin/nologin gfw
getent group gfw-ids >/dev/null 2>&1 || groupadd --system gfw-ids
id gfw-ids >/dev/null 2>&1 || useradd --system -g gfw-ids -d /nonexistent -s /sbin/nologin gfw-ids
getent group gfw-capture >/dev/null 2>&1 || groupadd --system gfw-capture
id gfw-capture >/dev/null 2>&1 || useradd --system -g gfw-capture -d /nonexistent -s /sbin/nologin gfw-capture
install -d -m 0750 -o root -g gfw /etc/gfw /etc/gfw/tls
if [ ! -e /etc/gfw/vpn-auth.key ]; then
    vpn_auth_key=$(mktemp /etc/gfw/.vpn-auth.XXXXXX)
    trap 'rm -f "$vpn_auth_key"' EXIT
    openssl rand -hex 32 > "$vpn_auth_key"
    chown root:gfw "$vpn_auth_key"
    chmod 0640 "$vpn_auth_key"
    mv "$vpn_auth_key" /etc/gfw/vpn-auth.key
    trap - EXIT
fi
install -d -m 0700 -o root -g root /etc/gfw/ids
for name in classification.config reference.config; do
    install -m 0600 -o root -g root "/etc/suricata/$name" "/etc/gfw/ids/$name"
done
install -d -m 0700 -o gfw -g gfw /var/lib/gfw
install -d -m 0700 -o root -g root /var/lib/gfw-agent
if [ -f /etc/altlinux-release ]; then install -d -m 0755 /etc/net/ifaces; fi
if [ ! -d /etc/sysctl.d ]; then install -d -m 0755 /etc/sysctl.d; fi
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi
# No network changes and no service starts on installation/upgrade.
