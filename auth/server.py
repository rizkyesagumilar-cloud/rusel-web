#!/usr/bin/env python3
import base64
import hashlib
import hmac
import html
import json
import os
import time
import urllib.parse
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOGIN_URL = os.environ["RUSEL_LOGIN_URL"].strip()
EXCHANGE_URL = os.environ["RUSEL_EXCHANGE_URL"].strip()
SESSION_SECRET = os.environ["RUSEL_AUTH_SECRET"].encode("utf-8")
ALLOWED = {
    "esa@rhayagroup.com",
    "kolspecialistruselco@gmail.com",
}
COOKIE_NAME = "rusel_session"
RD_COOKIE = "rusel_rd"
SESSION_TTL = 12 * 60 * 60

def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

def b64ud(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))

def sign(payload: str) -> str:
    return b64u(hmac.new(SESSION_SECRET, payload.encode("ascii"), hashlib.sha256).digest())

def mint_session(email: str) -> str:
    payload = b64u(json.dumps(
        {"email": email, "exp": int(time.time()) + SESSION_TTL},
        separators=(",", ":"),
    ).encode("utf-8"))
    return payload + "." + sign(payload)

def verify_session(token: str):
    try:
        payload, sig = token.split(".", 1)
        if not hmac.compare_digest(sign(payload), sig):
            return None
        data = json.loads(b64ud(payload))
        email = str(data.get("email", "")).strip().lower()
        exp = int(data.get("exp", 0))
        if email not in ALLOWED or exp <= int(time.time()):
            return None
        return email
    except Exception:
        return None

def parse_cookies(header: str):
    jar = cookies.SimpleCookie()
    try:
        jar.load(header or "")
    except Exception:
        return {}
    return {k: v.value for k, v in jar.items()}

def safe_rd(value: str) -> str:
    value = urllib.parse.unquote(value or "/")
    if not value.startswith("/") or value.startswith("//"):
        return "/"
    if "\\" in value or "\r" in value or "\n" in value:
        return "/"
    return value[:2000]

def page(title: str, body: str) -> bytes:
    return f"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}
body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#090f20;color:#eef2ff;font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,sans-serif}}
.card{{width:min(430px,calc(100vw - 32px));padding:36px;border:1px solid #26345b;border-radius:20px;background:#121b33;box-shadow:0 24px 80px #0008}}
.brand{{font-size:13px;letter-spacing:.16em;color:#91a7ff;font-weight:700;margin-bottom:14px}}
h1{{font-size:30px;line-height:1.15;margin:0 0 12px}}p{{color:#b7c1dc;margin:0 0 26px}}
a.btn{{display:block;text-align:center;padding:13px 18px;border-radius:10px;background:#f8fafc;color:#0b1020;text-decoration:none;font-weight:700}}
.note{{font-size:12px;color:#7f8baa;margin-top:18px;text-align:center}}
</style></head><body><main class="card"><div class="brand">RUSEL CO</div>{body}</main></body></html>""".encode("utf-8")

class Handler(BaseHTTPRequestHandler):
    server_version = "RuselAuth/1.0"

    def log_message(self, fmt, *args):
        return

    def send_common(self, status, content_type="text/plain; charset=utf-8", extra=None):
        self.send_response(status)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Type", content_type)
        for k, v in (extra or []):
            self.send_header(k, v)
        self.end_headers()

    def redirect(self, location, headers=None):
        self.send_common(302, extra=[("Location", location)] + (headers or []))

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)
        jar = parse_cookies(self.headers.get("Cookie", ""))

        if path == "/healthz":
            self.send_common(200)
            self.wfile.write(b"ok")
            return

        if path == "/auth/verify":
            email = verify_session(jar.get(COOKIE_NAME, ""))
            if email:
                self.send_common(200, extra=[("X-Auth-Email", email)])
                self.wfile.write(b"ok")
                return
            rd = safe_rd(self.headers.get("X-Forwarded-Uri", "/"))
            self.redirect("/auth/signin?rd=" + urllib.parse.quote(rd, safe=""))
            return

        if path == "/auth/signin":
            email = verify_session(jar.get(COOKIE_NAME, ""))
            if email:
                self.redirect(safe_rd(query.get("rd", ["/"])[0]))
                return
            rd = safe_rd(query.get("rd", ["/"])[0])
            href = "/auth/login?rd=" + urllib.parse.quote(rd, safe="")
            body = (
                "<h1>Marketing Web Apps</h1>"
                "<p>Akses terbatas. Masuk menggunakan akun Google yang telah diizinkan.</p>"
                f'<a class="btn" href="{html.escape(href, quote=True)}">Masuk dengan Google</a>'
                '<div class="note">Hanya akun internal yang terdaftar dapat membuka situs ini.</div>'
            )
            data = page("RUSEL CO — Login", body)
            self.send_common(200, "text/html; charset=utf-8", [
                ("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'"),
            ])
            self.wfile.write(data)
            return

        if path == "/auth/login":
            rd = safe_rd(query.get("rd", ["/"])[0])
            headers = [(
                "Set-Cookie",
                f"{RD_COOKIE}={urllib.parse.quote(rd, safe='')}; Path=/auth/; Max-Age=300; Secure; HttpOnly; SameSite=Lax",
            )]
            self.redirect(LOGIN_URL, headers)
            return

        if path == "/auth/callback":
            code = query.get("code", [""])[0]
            if not code or len(code) > 256:
                data = page("RUSEL CO — Login gagal", "<h1>Login gagal</h1><p>Kode login tidak valid. Silakan coba lagi.</p><a class=\"btn\" href=\"/auth/signin\">Kembali</a>")
                self.send_common(400, "text/html; charset=utf-8")
                self.wfile.write(data)
                return
            try:
                url = EXCHANGE_URL + "?" + urllib.parse.urlencode({"action": "exchange", "code": code})
                req = urllib.request.Request(url, headers={"User-Agent": "RuselAuth/1.0"})
                with urllib.request.urlopen(req, timeout=10) as response:
                    result = json.loads(response.read().decode("utf-8"))
                email = str(result.get("email", "")).strip().lower()
                if not result.get("ok") or email not in ALLOWED:
                    raise ValueError("unauthorized")
            except Exception:
                data = page("RUSEL CO — Akses ditolak", "<h1>Akses ditolak</h1><p>Akun Google ini tidak memiliki izin untuk membuka RUSEL CO.</p><a class=\"btn\" href=\"/auth/signin\">Coba akun lain</a>")
                self.send_common(403, "text/html; charset=utf-8")
                self.wfile.write(data)
                return

            rd = safe_rd(jar.get(RD_COOKIE, "/"))
            session = mint_session(email)
            headers = [
                ("Set-Cookie", f"{COOKIE_NAME}={session}; Path=/; Max-Age={SESSION_TTL}; Secure; HttpOnly; SameSite=Lax"),
                ("Set-Cookie", f"{RD_COOKIE}=; Path=/auth/; Max-Age=0; Secure; HttpOnly; SameSite=Lax"),
            ]
            self.redirect(rd, headers)
            return

        if path == "/auth/logout":
            headers = [("Set-Cookie", f"{COOKIE_NAME}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax")]
            self.redirect("/auth/signin", headers)
            return

        self.send_common(404)
        self.wfile.write(b"not found")

if __name__ == "__main__":
    if len(SESSION_SECRET) < 32:
        raise SystemExit("RUSEL_AUTH_SECRET must be at least 32 bytes")
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
