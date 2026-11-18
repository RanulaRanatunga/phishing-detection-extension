#!/usr/bin/env python3
from __future__ import annotations

import argparse
import html
import mimetypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


BASE_DIR = Path(__file__).resolve().parent

HOST_TO_FILE = {
    "verify-paypal-login.test": "paypal-account-verify-login.html",
    "bank-security-alert.test": "bank-confirm-signin.html",
    "microsoft-auth-check.test": "microsoft-secure-password-update.html",
    "local-docs": "document-review-request.html",
    "localhost-review": "team-shared-file-check.html",
}


def build_index_page(port: int) -> bytes:
    rows = []
    for host, filename in HOST_TO_FILE.items():
        label = "phishing" if host.endswith(".test") else "suspicious"
        url = f"http://{host}:{port}/" if port != 80 else f"http://{host}/"
        rows.append(
            f"<li><strong>{html.escape(label.title())}</strong>: "
            f"<a href=\"{html.escape(url)}\">{html.escape(url)}</a> "
            f"&rarr; {html.escape(filename)}</li>"
        )

    hosts_line = "127.0.0.1 " + " ".join(HOST_TO_FILE.keys())
    page = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hosted Demo Sites</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 32px; background: #f5f5f5; color: #222; }}
    main {{ max-width: 860px; margin: 0 auto; background: #fff; padding: 24px; border-radius: 10px; }}
    code {{ background: #f0f0f0; padding: 2px 6px; border-radius: 4px; }}
    li {{ margin: 10px 0; }}
  </style>
</head>
<body>
  <main>
    <h1>Hosted Demo Sites</h1>
    <p>This local server maps demo hostnames to the packaged phishing-test pages.</p>
    <p>Add this line to <code>/etc/hosts</code> before testing:</p>
    <p><code>{html.escape(hosts_line)}</code></p>
    <p>Then open one of these URLs:</p>
    <ul>
      {''.join(rows)}
    </ul>
  </main>
</body>
</html>"""
    return page.encode("utf-8")


class DemoHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802 - stdlib interface
        host = (self.headers.get("Host") or "").split(":", 1)[0].lower()
        url_path = urlsplit(self.path).path or "/"

        mapped_file = HOST_TO_FILE.get(host)
        if mapped_file and url_path in {"/", "/index.html"}:
            return self._serve_file(BASE_DIR / mapped_file)

        # Fallback: allow direct file access for local browsing/debugging.
        candidate = (BASE_DIR / url_path.lstrip("/")).resolve()
        if candidate.is_file() and candidate.parent == BASE_DIR:
            return self._serve_file(candidate)

        if url_path in {"/", "/index.html"}:
            body = build_index_page(self.server.server_port)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404, "Not Found")

    def log_message(self, format: str, *args) -> None:  # noqa: A003 - stdlib interface
        return

    def _serve_file(self, path: Path) -> None:
        body = path.read_bytes()
        content_type, _ = mimetypes.guess_type(str(path))
        self.send_response(200)
        self.send_header("Content-Type", content_type or "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve hosted phishing demo pages by hostname.")
    parser.add_argument("--bind", default="127.0.0.1", help="IP address to bind to")
    parser.add_argument("--port", type=int, default=80, help="Port to listen on")
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.bind, args.port), DemoHandler)
    print(f"Serving hosted demo pages on http://{args.bind}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
