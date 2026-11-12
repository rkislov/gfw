#!/usr/bin/env python3
"""Verify real package upgrade and first login in a disposable Linux container."""

import argparse
from contextlib import contextmanager
import http.cookiejar
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import time
import urllib.error
import urllib.request

if os.environ.get("GFW_QUALIFICATION_LAB") != "1":
    raise SystemExit("Run only inside a fresh isolated Linux lab with GFW_QUALIFICATION_LAB=1.")

URL = "http://127.0.0.1:18088"
DATA = Path("/var/lib/gfw")
TOKEN_ONLY = Path("/state/token-only")
FRESH = Path("/state/fresh")
ADMIN_PASSWORD = "fixture legacy admin password"
USER_PASSWORD = "fixture legacy user password"
NEW_PASSWORD = "fixture replacement password"


def api(path, body=None, *, method="GET", opener=None, headers=None, expected=200):
    request = urllib.request.Request(
        URL + "/api/v1" + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    open_request = opener.open if opener is not None else urllib.request.urlopen
    try:
        with open_request(request, timeout=5) as response:
            assert response.status == expected, (path, response.status, expected)
            return json.load(response)
    except urllib.error.HTTPError as error:
        if error.code != expected:
            raise
        return None


@contextmanager
def controller(data, version):
    with open("/state/gfwd.log", "w+") as log, subprocess.Popen(
        ["/usr/sbin/gfwd", "-listen", "127.0.0.1:18088", "-data-dir", str(data)],
        stdout=log, stderr=log,
    ) as process:
        try:
            for _ in range(100):
                if process.poll() is not None:
                    break
                try:
                    with urllib.request.urlopen(URL + "/healthz", timeout=1):
                        break
                except OSError:
                    time.sleep(0.1)
            else:
                raise AssertionError("controller readiness timeout")
            if process.poll() is not None:
                log.seek(0)
                raise AssertionError(log.read())
            token = (data / "admin.token").read_text().strip()
            bearer = {"Authorization": "Bearer " + token}
            assert api("/status", headers=bearer)["version"] == version
            yield bearer
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def login(name, password, role=None, default=None):
    browser = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    api("/auth/login", {"username": name, "password": password}, method="POST",
        opener=browser, expected=200 if role else 401)
    if role:
        me = api("/auth/me", opener=browser)
        assert (me["user"], me["role"], me["personal"]) == (name, role, True), me
        if default is not None:
            assert me["default_password"] is default, me
        return browser, me["csrf"]


def save_user(name, role, password, headers, *, opener=None, revision=0):
    return api("/users", {"name": name, "source": "local", "role": role,
                          "revision": revision, "password": password},
               method="PUT", headers=headers, opener=opener)


def stored_users():
    database = DATA / "identity" / "identity.db"
    with sqlite3.connect(f"file:{database}?mode=ro", uri=True) as connection:
        return connection.execute(
            "SELECT name, password, revision FROM users ORDER BY name"
        ).fetchall()


def install(package):
    command = ["rpm", "-Uvh"] if package.endswith(".rpm") else ["dpkg", "-i"]
    subprocess.run([*command, package], check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("old")
    parser.add_argument("new")
    parser.add_argument("--from-version", default="0.22.5")
    parser.add_argument("--to-version", default="0.22.6")
    args = parser.parse_args()
    assert not (DATA / "identity" / "identity.db").exists()
    install(args.old)

    traffic = {"url": "http://127.0.0.1:18123", "database": "gfw_upgrade",
               "user": "gfw_upgrade", "password": "fixture ClickHouse password"}
    with controller(DATA, args.from_version) as headers:
        users = api("/users", headers=headers)
        admin_revision = next((u["revision"] for u in users if u["name"] == "admin"), 0)
        save_user("admin", "admin", ADMIN_PASSWORD, headers, revision=admin_revision)
        save_user("alice", "user", USER_PASSWORD, headers)
        login("admin", ADMIN_PASSWORD, "admin")
        login("alice", USER_PASSWORD, "user")
        api("/traffic/config", traffic, method="PUT", headers=headers)
        policy = api("/config", headers=headers)
        audit = api("/audit", headers=headers)
    with controller(TOKEN_ONLY, args.from_version) as headers:
        initial_users = api("/users", headers=headers)
        if initial_users:
            login("admin", "admin", "admin", True)
    original_users = stored_users()
    original_token = (DATA / "admin.token").read_bytes()
    token_only_key = (TOKEN_ONLY / "admin.token").read_bytes()
    traffic_path = DATA / "traffic" / "clickhouse"
    traffic_vault = traffic_path.read_bytes()

    install(args.new)
    with controller(DATA, args.to_version) as headers:
        login("admin", ADMIN_PASSWORD, "admin", False)
        login("alice", USER_PASSWORD, "user", False)
        login("admin", "admin")
        assert api("/config", headers=headers) == policy
        assert api("/audit", headers=headers) == audit
        traffic_cfg = api("/traffic/status", headers=headers)["config"]
        assert traffic_cfg == {key: value for key, value in traffic.items() if key != "password"}
        if args.to_version in ("0.22.5", "0.22.6"):
            siem = api("/siem", headers=headers)
            assert not siem["enabled"] and siem["traffic_stats"]["queued"] == 0
            filters = {"conntrack": ["destroy"], "nflog": ["drop"], "ip": "192.0.2.0/24",
                       "port": 443, "protocol": 6, "rule": "drop-web", "direction": "forward"}
            api("/siem", {"revision": siem["revision"], "enabled": False,
                          "address": "siem.example.org:6514", "transport": "tls", "traffic": filters},
                method="PUT", headers=headers)
    assert stored_users() == original_users, "upgrade changed stored user records"
    assert (DATA / "admin.token").read_bytes() == original_token
    assert traffic_path.read_bytes() == traffic_vault
    with controller(TOKEN_ONLY, args.to_version) as headers:
        assert api("/users", headers=headers) == initial_users
        if initial_users:
            login("admin", "admin", "admin", True)
        else:
            login("admin", "admin")
    assert (TOKEN_ONLY / "admin.token").read_bytes() == token_only_key
    print(f"PASS: {args.from_version} -> {args.to_version} preserves accounts, recovery tokens, policy, audit and ClickHouse settings", flush=True)

    if args.to_version in ("0.22.5", "0.22.6"):
        with controller(DATA, args.to_version) as headers:
            saved_siem = api("/siem", headers=headers)
            assert not saved_siem["enabled"] and saved_siem["traffic"] == filters
        print("PASS: CEF filters persist after controller restart", flush=True)

    with controller(FRESH, args.to_version) as headers:
        browser, csrf = login("admin", "admin", "admin", True)
        admin, = api("/users", headers=headers)
        save_user("admin", "admin", NEW_PASSWORD, {"X-GFW-CSRF": csrf},
                  opener=browser, revision=admin["revision"])
    with controller(FRESH, args.to_version):
        login("admin", NEW_PASSWORD, "admin", False)
        login("admin", "admin")
    print("PASS: fresh install accepts admin/admin and clears first-login warning after password change", flush=True)


if __name__ == "__main__":
    main()
