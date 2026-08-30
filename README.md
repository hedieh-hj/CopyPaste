# Temporary Clipboard

A lightweight, account-free web clipboard for transferring text, links, and code snippets between devices.

## Features

- Short, cryptographically random access codes
- Shareable clipboard links
- Expiration times from 5 minutes to 24 hours
- Optional password protection
- Delete after the first successful view
- Manual deletion with an owner-only token
- Live expiration countdown
- Server-generated QR codes
- Responsive dark interface with RTL support
- Request rate limiting and content-size limits

## Requirements

- Python 3.10 or newer
- The optional `qrcode` Python package for QR code generation

The clipboard API and web interface otherwise use only Python's standard library and vanilla HTML, CSS, and JavaScript.

## Run Locally

```powershell
python server.py
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000) in your browser.

To make the application available to other devices on your local network, bind it to all network interfaces:

```powershell
$env:CLIPBOARD_HOST = "0.0.0.0"
python server.py
```

You can also change the listening port:

```powershell
$env:PORT = "8080"
python server.py
```

## Run Tests

```powershell
python -m unittest discover -s tests -v
```

## Security Model

- Clipboard content is stored only in process memory. It is never written to a file or database.
- Access codes are generated with a cryptographically secure random generator.
- Passwords are hashed with `scrypt` and a unique random salt.
- Request bodies, clipboard content, access codes, and full URLs are excluded from server logs.
- Clipboard creation and retrieval endpoints are rate-limited.
- Clipboard content is limited to 20,000 characters.
- Responses use `Cache-Control: no-store` and additional security headers.
- Expired entries are removed from the in-memory store during subsequent operations.

This application is not intended for passwords, banking details, or highly confidential information.

## Production Notes

The included in-memory store is intended for a single-process deployment. For a multi-instance production setup, replace it with Redis using atomic TTLs. Disable Redis persistence and command logging if clipboard content must never be written to disk.

Run the application behind an HTTPS reverse proxy, configure trusted proxy headers carefully, and add infrastructure-level rate limiting before exposing it publicly.

## License

No license has been selected yet.
