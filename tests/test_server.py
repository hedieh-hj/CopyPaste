import json
import threading
import time
import unittest
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import server


class ApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.port = cls.httpd.server_port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls): cls.httpd.shutdown()

    def request(self, method, path, body=None, headers=None):
        conn = HTTPConnection("127.0.0.1", self.port)
        payload = json.dumps(body).encode() if body is not None else None
        hs = {"Content-Type": "application/json", **(headers or {})}
        conn.request(method, path, payload, hs)
        response = conn.getresponse()
        data = json.loads(response.read())
        conn.close()
        return response.status, data

    def create(self, **overrides):
        body = {"content": "hello", "ttl": 300, "burn": False, **overrides}
        return self.request("POST", "/api/clipboards", body)

    def test_create_and_open(self):
        status, created = self.create()
        self.assertEqual(status, 201)
        status, opened = self.request("POST", f"/api/clipboards/{created['code']}/open", {})
        self.assertEqual((status, opened["content"]), (200, "hello"))

    def test_burn_after_read(self):
        _, created = self.create(burn=True)
        self.assertEqual(self.request("POST", f"/api/clipboards/{created['code']}/open", {})[0], 200)
        self.assertEqual(self.request("POST", f"/api/clipboards/{created['code']}/open", {})[0], 404)

    def test_password_and_manual_delete(self):
        _, created = self.create(password="secret")
        path = f"/api/clipboards/{created['code']}/open"
        self.assertEqual(self.request("POST", path, {})[0], 401)
        self.assertEqual(self.request("POST", path, {"password": "bad"})[0], 403)
        self.assertEqual(self.request("POST", path, {"password": "secret"})[0], 200)
        headers = {"X-Delete-Token": created["delete_token"]}
        self.assertEqual(self.request("DELETE", f"/api/clipboards/{created['code']}", headers=headers)[0], 200)

    def test_expiration_cleanup(self):
        code, item = server.STORE.create("short", 300, False, None)
        item["expires_at"] = time.time() - 1
        self.assertEqual(self.request("GET", f"/api/clipboards/{code}")[0], 404)


if __name__ == "__main__": unittest.main()
