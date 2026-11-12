#!/usr/bin/env python3
"""Verify real package upgrade and first login in a disposable Linux container."""

from contextlib import contextmanager
import http.cookiejar
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
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
    old, new = sys.argv[1:]
    assert not (DATA / "identity" / "identity.db").exists()
    install(old)
    with controller(DATA, "0.22.3") as headers:
        save_user("admin", "admin", ADMIN_PASSWORD, headers)
        save_user("alice", "user", USER_PASSWORD, headers)
        login("admin", ADMIN_PASSWORD, "admin")
        login("alice", USER_PASSWORD, "user")
    with controller(TOKEN_ONLY, "0.22.3") as headers:
        assert api("/users", headers=headers) == []
    original_users = stored_users()
    original_token = (DATA / "admin.token").read_bytes()
    token_only_key = (TOKEN_ONLY / "admin.token").read_bytes()

    install(new)
    with controller(DATA, "0.22.4"):
        login("admin", ADMIN_PASSWORD, "admin", False)
        login("alice", USER_PASSWORD, "user", False)
        login("admin", "admin")
    assert stored_users() == original_users, "upgrade changed stored user records"
    assert (DATA / "admin.token").read_bytes() == original_token
    with controller(TOKEN_ONLY, "0.22.4") as headers:
        assert api("/users", headers=headers) == []
        login("admin", "admin")
    assert (TOKEN_ONLY / "admin.token").read_bytes() == token_only_key
    print("PASS: 0.22.3 -> 0.22.4 preserves password hashes, roles and recovery tokens", flush=True)

    with controller(FRESH, "0.22.4") as headers:
        browser, csrf = login("admin", "admin", "admin", True)
        admin, = api("/users", headers=headers)
        save_user("admin", "admin", NEW_PASSWORD, {"X-GFW-CSRF": csrf},
                  opener=browser, revision=admin["revision"])
    with controller(FRESH, "0.22.4"):
        login("admin", NEW_PASSWORD, "admin", False)
        login("admin", "admin")
    print("PASS: fresh install accepts admin/admin and clears first-login warning after password change", flush=True)


if __name__ == "__main__":
    main()
