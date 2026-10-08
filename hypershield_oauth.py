#!/usr/bin/env python3
"""Microsoft Entra/OIDC bearer-token helper for Hypershield/Timescape.

This module is used by import_hs_policy.py, but can also be run directly:

    python hypershield_oauth.py

Configuration is read from normal environment variables and, if present, a
.env file in the same directory as this module. Existing environment variables
take precedence over .env values.

Required:
    HYPERSHIELD_ISSUER
    HYPERSHIELD_CLIENT_ID
    HYPERSHIELD_CLIENT_SECRET

Optional:
    HYPERSHIELD_REDIRECT_URI     default http://localhost:5678/oauth2/callback
    HYPERSHIELD_SCOPES           default openid profile email
    SCOPES                       alias for HYPERSHIELD_SCOPES
    HYPERSHIELD_TOKEN_FILE       default hs_token.txt beside this file
    HS_OIDC_PROMPT               default select_account
    HS_OIDC_EXPECTED_ACCOUNT     optional preferred_username/email guard

The helper uses Authorization Code + PKCE (S256), performs OIDC discovery,
opens the user's browser, receives the loopback callback, exchanges the code,
writes the returned ID token to disk, and returns it to the caller.

The ID token is intentionally used as the Hypershield bearer token to preserve
the behavior of the previously working HyperShield GA token helper.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import json
import os
import secrets
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_ENV_FILE = SCRIPT_DIR / ".env"
DEFAULT_TOKEN_FILE = SCRIPT_DIR / "hs_token.txt"
DEFAULT_REDIRECT_URI = "http://localhost:5678/oauth2/callback"
DEFAULT_SCOPES = "openid profile email"
REQUEST_TIMEOUT = 15


def load_env_file(path: Path = DEFAULT_ENV_FILE) -> None:
    """Load a small dotenv-compatible KEY=VALUE file without extra dependencies."""
    if not path.is_file():
        return

    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if not key:
            continue
        if (
            len(value) >= 2
            and value[0] == value[-1]
            and value[0] in {"'", '"'}
        ):
            value = value[1:-1]
        os.environ.setdefault(key, value)


def normalize_issuer(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw.rstrip("/")
    return f"https://login.microsoftonline.com/{raw}/v2.0"


def http_json(
    url: str,
    *,
    data: dict[str, str] | None = None,
    headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    encoded = None
    if data is not None:
        encoded = urllib.parse.urlencode(data).encode("utf-8")

    request = urllib.request.Request(
        url,
        data=encoded,
        headers=headers or {},
        method="POST" if encoded is not None else "GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT) as response:
            raw = response.read().decode("utf-8")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"OIDC request failed: HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"OIDC request failed: {exc.reason}") from exc

    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError("OIDC endpoint returned invalid JSON") from exc


def discover(issuer: str) -> dict[str, Any]:
    return http_json(issuer.rstrip("/") + "/.well-known/openid-configuration")


def gen_pkce_pair() -> tuple[str, str]:
    verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32))
        .rstrip(b"=")
        .decode("ascii")
    )
    challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(verifier.encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    return verifier, challenge


def basic_auth_header(client_id: str, client_secret: str) -> str:
    # Preserve the auth style used by the previously working helper.
    creds = (
        f"{urllib.parse.quote_plus(client_id)}:"
        f"{urllib.parse.quote_plus(client_secret)}"
    )
    return "Basic " + base64.b64encode(creds.encode("utf-8")).decode("ascii")


def exchange_token(
    token_endpoint: str,
    client_id: str,
    client_secret: str,
    form: dict[str, str],
) -> dict[str, Any]:
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": basic_auth_header(client_id, client_secret),
    }

    try:
        return http_json(token_endpoint, data=form, headers=headers)
    except RuntimeError:
        # Entra deployments can differ in the accepted client-auth style.
        fallback = dict(form)
        fallback["client_id"] = client_id
        fallback["client_secret"] = client_secret
        return http_json(
            token_endpoint,
            data=fallback,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )


def decode_jwt_unverified(token: str) -> dict[str, Any] | None:
    """Decode JWT metadata only. This is not signature validation."""
    try:
        parts = token.split(".")
        if len(parts) < 2:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None


def token_is_fresh(token: str, minimum_lifetime: int = 60) -> bool:
    payload = decode_jwt_unverified(token)
    if not payload:
        return False
    exp = payload.get("exp")
    return isinstance(exp, (int, float)) and exp > time.time() + minimum_lifetime


def write_token_file(token: str, destination: Path) -> Path:
    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)

    fd, temp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        dir=str(destination.parent),
        text=True,
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(token)
            fh.flush()
            os.fsync(fh.fileno())

        try:
            os.chmod(temp_name, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass

        os.replace(temp_name, destination)

        try:
            os.chmod(destination, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)

    return destination


def _html(title: str, message: str) -> bytes:
    body = f"""<!doctype html>
<html>
<head><meta charset="utf-8"><title>{title}</title></head>
<body style="font-family:system-ui,sans-serif;max-width:720px;margin:5rem auto">
<h1>{title}</h1>
<p>{message}</p>
<p>You can close this tab.</p>
</body>
</html>"""
    return body.encode("utf-8")


def acquire_token(
    *,
    force_refresh: bool = False,
    token_file: Path | None = None,
) -> str:
    """Return a usable Hypershield bearer token, acquiring one interactively if needed."""
    load_env_file()

    configured_token_file = token_file or Path(
        os.environ.get("HYPERSHIELD_TOKEN_FILE", str(DEFAULT_TOKEN_FILE))
    )

    if not force_refresh and configured_token_file.is_file():
        existing = configured_token_file.read_text(encoding="utf-8").strip()
        if existing and token_is_fresh(existing):
            print(f"[auth] using unexpired token from {configured_token_file}")
            return existing

    issuer_raw = os.environ.get("HYPERSHIELD_ISSUER", "").strip()
    client_id = os.environ.get("HYPERSHIELD_CLIENT_ID", "").strip()
    client_secret = os.environ.get("HYPERSHIELD_CLIENT_SECRET", "").strip()
    redirect_uri = os.environ.get(
        "HYPERSHIELD_REDIRECT_URI", DEFAULT_REDIRECT_URI
    ).strip()
    scopes = (
        os.environ.get("SCOPES")
        or os.environ.get("HYPERSHIELD_SCOPES")
        or DEFAULT_SCOPES
    ).strip()
    prompt = os.environ.get("HS_OIDC_PROMPT", "select_account").strip()
    expected_account = os.environ.get("HS_OIDC_EXPECTED_ACCOUNT", "").strip()

    missing = [
        name
        for name, value in (
            ("HYPERSHIELD_ISSUER", issuer_raw),
            ("HYPERSHIELD_CLIENT_ID", client_id),
            ("HYPERSHIELD_CLIENT_SECRET", client_secret),
        )
        if not value
    ]
    if missing:
        raise RuntimeError(
            "Missing OAuth configuration: "
            + ", ".join(missing)
            + ". Put the values in .env or the process environment."
        )

    parsed_redirect = urllib.parse.urlparse(redirect_uri)
    if parsed_redirect.scheme != "http":
        raise RuntimeError("HYPERSHIELD_REDIRECT_URI must use http:// for loopback auth")
    if parsed_redirect.hostname not in {"localhost", "127.0.0.1"}:
        raise RuntimeError("HYPERSHIELD_REDIRECT_URI must use localhost or 127.0.0.1")
    if not parsed_redirect.port:
        raise RuntimeError("HYPERSHIELD_REDIRECT_URI must include a port")
    if parsed_redirect.path != "/oauth2/callback":
        raise RuntimeError(
            "HYPERSHIELD_REDIRECT_URI path must be /oauth2/callback"
        )

    discovery = discover(normalize_issuer(issuer_raw))
    authorization_endpoint = discovery.get("authorization_endpoint")
    token_endpoint = discovery.get("token_endpoint")
    if not authorization_endpoint or not token_endpoint:
        raise RuntimeError(
            "OIDC discovery document is missing authorization_endpoint/token_endpoint"
        )

    state = secrets.token_urlsafe(32)
    nonce = secrets.token_urlsafe(32)
    verifier, challenge = gen_pkce_pair()

    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
        "nonce": nonce,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if prompt:
        params["prompt"] = prompt

    authorization_url = (
        authorization_endpoint + "?" + urllib.parse.urlencode(params)
    )

    callback_result: dict[str, str] = {}

    class CallbackHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            return

        def do_GET(self) -> None:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/oauth2/callback":
                self.send_response(404)
                self.end_headers()
                return

            query = urllib.parse.parse_qs(parsed.query)
            callback_result["state"] = query.get("state", [""])[0]
            callback_result["code"] = query.get("code", [""])[0]
            callback_result["error"] = query.get("error", [""])[0]
            callback_result["error_description"] = query.get(
                "error_description", [""]
            )[0]

            success = bool(callback_result["code"]) and not callback_result["error"]
            body = _html(
                "Hypershield authentication complete" if success
                else "Hypershield authentication failed",
                "Return to the terminal."
            )
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = http.server.HTTPServer(
        (parsed_redirect.hostname, parsed_redirect.port),
        CallbackHandler,
    )

    print(f"[auth] callback: {redirect_uri}")
    print("[auth] opening Microsoft Entra sign-in...")
    if not webbrowser.open(authorization_url, new=1, autoraise=True):
        print("[auth] browser did not open automatically; open this URL:")
        print(authorization_url)

    try:
        server.handle_request()
    finally:
        server.server_close()

    if callback_result.get("error"):
        raise RuntimeError(
            "Entra returned "
            f"{callback_result['error']}: "
            f"{callback_result.get('error_description', '')}"
        )

    if not secrets.compare_digest(callback_result.get("state", ""), state):
        raise RuntimeError("OAuth state validation failed")

    code = callback_result.get("code")
    if not code:
        raise RuntimeError("OAuth callback did not include an authorization code")

    token_json = exchange_token(
        token_endpoint,
        client_id,
        client_secret,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "code_verifier": verifier,
        },
    )

    bearer = token_json.get("id_token")
    if not bearer:
        raise RuntimeError(
            "Token endpoint succeeded but returned no id_token"
        )

    payload = decode_jwt_unverified(bearer)
    if payload:
        if payload.get("nonce") != nonce:
            raise RuntimeError("ID-token nonce validation failed")

        account = (
            payload.get("preferred_username")
            or payload.get("email")
            or ""
        )
        if expected_account and account.lower() != expected_account.lower():
            raise RuntimeError(
                f"Signed in as {account or 'unknown account'}, "
                f"not {expected_account}"
            )

    destination = write_token_file(bearer, configured_token_file)
    print(f"[auth] token written to {destination}")
    return bearer


def main() -> int:
    try:
        token = acquire_token(force_refresh=True)
        payload = decode_jwt_unverified(token) or {}
        exp = payload.get("exp")
        print("[auth] token acquired successfully")
        if exp:
            print(
                "[auth] expires: "
                + time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(exp))
            )
        return 0
    except Exception as exc:
        print(f"[auth] ERROR: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
