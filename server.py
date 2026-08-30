"""Temporary Clipboard — dependency-free HTTP API and static file server."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

try:
    import qrcode
except ImportError:  # QR is optional; the rest of the app still runs.
    qrcode = None

HOST = os.getenv("CLIPBOARD_HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
MAX_BODY = 64 * 1024
MAX_CONTENT = 20_000
ALLOWED_TTLS = {300, 900, 3600, 21600, 86400}
CODE_ALPHABET = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
CODE_RE = re.compile(r"^[2-9A-HJ-NP-Z]{6}$")
STATIC = Path(__file__).parent / "static"


class Store:
    def __init__(self):
        self.items: dict[str, dict] = {}
        self.lock = threading.RLock()

    def cleanup(self):
        now = time.time()
        with self.lock:
            for code in [c for c, item in self.items.items() if item["expires_at"] <= now]:
                del self.items[code]

    def create(self, content: str, ttl: int, burn: bool, password: str | None):
        self.cleanup()
        with self.lock:
            for _ in range(20):
                code = "".join(secrets.choice(CODE_ALPHABET) for _ in range(6))
                if code not in self.items:
                    break
            else:
                raise RuntimeError("code allocation failed")
            salt = secrets.token_bytes(16) if password else None
            password_hash = (
                hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1)
                if password else None
            )
            item = {
                "content": content,
                "created_at": time.time(),
                "expires_at": time.time() + ttl,
                "burn": bool(burn),
                "salt": salt,
                "password_hash": password_hash,
                "delete_token": secrets.token_urlsafe(32),
            }
            self.items[code] = item
            return code, item

    def get(self, code: str, password: str | None):
        self.cleanup()
        with self.lock:
            item = self.items.get(code)
            if not item:
                return "missing", None
            if item["password_hash"] is not None:
                if not password:
                    return "password", None
                candidate = hashlib.scrypt(password.encode(), salt=item["salt"], n=2**14, r=8, p=1)
                if not hmac.compare_digest(candidate, item["password_hash"]):
                    return "wrong_password", None
            result = {"content": item["content"], "expires_at": item["expires_at"], "burned": item["burn"]}
            if item["burn"]:
                del self.items[code]
            return "ok", result

    def metadata(self, code: str):
        self.cleanup()
        with self.lock:
            item = self.items.get(code)
            if not item:
                return None
            return {
                "expires_at": item["expires_at"],
                "protected": item["password_hash"] is not None,
                "burn": item["burn"],
            }

    def delete(self, code: str, token: str):
        self.cleanup()
        with self.lock:
            item = self.items.get(code)
            if not item or not hmac.compare_digest(item["delete_token"], token):
                return False
            del self.items[code]
            return True


STORE = Store()


class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str, limit: int, window: int):
        now = time.time()
        with self.lock:
            bucket = self.hits[key]
            while bucket and bucket[0] < now - window:
                bucket.popleft()
            if len(bucket) >= limit:
                return False
            bucket.append(now)
            return True


LIMITER = RateLimiter()


class Handler(BaseHTTPRequestHandler):
    server_version = "TemporaryClipboard/1.0"

    def log_message(self, fmt, *args):
        # Deliberately avoid URLs, request bodies, codes and query parameters in logs.
        print(f"{self.address_string()} - {args[1] if len(args) > 1 else '-'}")

    def security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")

    def send_json(self, status, payload):
        data = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)

    def read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    @property
    def client_ip(self):
        return self.client_address[0]

    def do_POST(self):
        path = urlparse(self.path).path
        if path == "/api/clipboards":
            if not LIMITER.allow(f"create:{self.client_ip}", 20, 600):
                return self.send_json(429, {"error": "درخواست‌های بیش از حد؛ کمی بعد دوباره تلاش کنید."})
            data = self.read_json()
            if not isinstance(data, dict):
                return self.send_json(400, {"error": "درخواست نامعتبر است."})
            content = data.get("content")
            ttl = data.get("ttl")
            password = data.get("password") or None
            if not isinstance(content, str) or not content.strip() or len(content) > MAX_CONTENT:
                return self.send_json(400, {"error": f"متن باید بین ۱ تا {MAX_CONTENT:,} نویسه باشد."})
            if ttl not in ALLOWED_TTLS:
                return self.send_json(400, {"error": "زمان انقضا معتبر نیست."})
            if password is not None and (not isinstance(password, str) or not 4 <= len(password) <= 128):
                return self.send_json(400, {"error": "رمز باید حداقل ۴ نویسه باشد."})
            code, item = STORE.create(content, ttl, bool(data.get("burn")), password)
            return self.send_json(201, {
                "code": code,
                "expires_at": item["expires_at"],
                "delete_token": item["delete_token"],
                "url": f"{self.origin()}/clipboard/{code}",
            })

        match = re.fullmatch(r"/api/clipboards/([^/]+)/open", path)
        if match:
            if not LIMITER.allow(f"open:{self.client_ip}", 40, 600):
                return self.send_json(429, {"error": "تلاش‌های بیش از حد؛ کمی بعد دوباره تلاش کنید."})
            code = match.group(1).upper()
            if not CODE_RE.fullmatch(code):
                return self.send_json(404, {"error": "کلیپ‌بورد پیدا نشد یا منقضی شده است."})
            data = self.read_json() or {}
            status, item = STORE.get(code, data.get("password"))
            if status == "password":
                return self.send_json(401, {"error": "این کلیپ‌بورد رمز دارد.", "password_required": True})
            if status == "wrong_password":
                return self.send_json(403, {"error": "رمز واردشده درست نیست.", "password_required": True})
            if status == "missing":
                return self.send_json(404, {"error": "کلیپ‌بورد پیدا نشد یا منقضی شده است."})
            return self.send_json(200, item)
        self.send_error(404)

    def do_DELETE(self):
        match = re.fullmatch(r"/api/clipboards/([^/]+)", urlparse(self.path).path)
        if not match:
            return self.send_error(404)
        token = self.headers.get("X-Delete-Token", "")
        if STORE.delete(match.group(1).upper(), token):
            return self.send_json(200, {"deleted": True})
        self.send_json(404, {"error": "کلیپ‌بورد پیدا نشد یا اجازه حذف ندارید."})

    def do_GET(self):
        parsed = urlparse(self.path)
        match = re.fullmatch(r"/api/clipboards/([^/]+)", parsed.path)
        if match:
            code = match.group(1).upper()
            item = STORE.metadata(code) if CODE_RE.fullmatch(code) else None
            return self.send_json(200, item) if item else self.send_json(404, {"error": "کلیپ‌بورد پیدا نشد یا منقضی شده است."})
        if parsed.path == "/api/qr":
            if qrcode is None:
                return self.send_json(501, {"error": "قابلیت QR در دسترس نیست."})
            value = parse_qs(parsed.query).get("value", [""])[0]
            if not value.startswith(self.origin() + "/clipboard/") or len(value) > 300:
                return self.send_json(400, {"error": "پیوند نامعتبر است."})
            image = qrcode.make(value)
            output = io.BytesIO()
            image.save(output, format="PNG")
            data = output.getvalue()
            self.send_response(200)
            self.send_header("Content-Type", "image/png")
            self.send_header("Content-Length", str(len(data)))
            self.security_headers()
            self.end_headers()
            return self.wfile.write(data)
        self.serve_static(parsed.path)

    def origin(self):
        proto = self.headers.get("X-Forwarded-Proto", "http").split(",")[0].strip()
        host = self.headers.get("Host", f"{HOST}:{PORT}")
        return f"{proto}://{host}"

    def serve_static(self, path):
        requested = "index.html" if path == "/" or re.fullmatch(r"/clipboard/[2-9A-HJ-NP-Z]{6}", path, re.I) else path.lstrip("/")
        target = (STATIC / requested).resolve()
        if STATIC.resolve() not in target.parents or not target.is_file():
            return self.send_error(404)
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.security_headers()
        self.end_headers()
        self.wfile.write(data)


if __name__ == "__main__":
    print(f"Temporary Clipboard: http://{HOST}:{PORT}")
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
