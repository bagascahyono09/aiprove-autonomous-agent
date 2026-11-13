#!/usr/bin/env python3
"""Autonomous, dependency-free AIProve bounty agent.

The agent owns its identity, enters every open bounty, and only submits
predictions it can ground in the configured public market-data sources.
"""

import argparse
import datetime
import gzip
import hashlib
import hmac
import http.client
import json
import math
import os
import re
import secrets
import ssl
import stat
import sys
import time
import urllib.error
import urllib.parse
import urllib.request


DEFAULT_BASE_URL = "https://aiprove.fun"
DEFAULT_HANDLE = "autonomous-agent"
HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_KEY_PATH = os.path.join(HERE, "agent-key.hex")
REPORT_PATH = os.path.join(HERE, "run-report.json")
USER_AGENT = "AIProve-Autonomous-Agent/1.0"
HTTP_TIMEOUT = 30
MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# secp256k1 parameters. This crypto core is shared with the proven
# sample-agent-skillmd implementation in this project.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# Keccak-f[1600] constants. Keccak-256 uses different padding from SHA3-256.
_MASK64 = (1 << 64) - 1
_KECCAK_RC = (
    0x0000000000000001, 0x0000000000008082,
    0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001,
    0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088,
    0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B,
    0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080,
    0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080,
    0x0000000080000001, 0x8000000080008008,
)
_KECCAK_RHO = (
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
)
_KECCAK_PI = (
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
)


class StepError(Exception):
    """An error associated with one JSON status step."""

    def __init__(self, step, message):
        super().__init__(message)
        self.step = step
        self.message = message


class RequestError(StepError):
    """An HTTP error which may be safe to retry."""

    def __init__(self, step, message, retryable=False, status_code=None):
        super().__init__(step, message)
        self.retryable = retryable
        self.status_code = status_code


class DeferredEntryError(StepError):
    """A listed bounty whose opensAt gate has not passed yet."""

    def __init__(self, slug, submit_kind, message):
        super().__init__("enter_bounty", message)
        self.slug = slug
        self.submit_kind = submit_kind


def emit(step, status="ok", **fields):
    """Write one compact, secret-free JSON log record."""
    record = {"step": step, "status": status}
    record.update(fields)
    print(json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)


def utc_now():
    """Return a stable UTC timestamp suitable for the report."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds"
    ).replace("+00:00", "Z")


def utc_from_epoch_ms(value):
    """Convert an API millisecond timestamp to UTC, if valid."""
    try:
        timestamp = float(value) / 1000.0
        return datetime.datetime.fromtimestamp(
            timestamp, datetime.timezone.utc
        ).isoformat(timespec="seconds").replace("+00:00", "Z")
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _rotl64(value, count):
    return ((value << count) | (value >> (64 - count))) & _MASK64


def _keccak_f1600(state):
    for rc in _KECCAK_RC:
        # Theta.
        columns = [
            state[x] ^ state[x + 5] ^ state[x + 10] ^
            state[x + 15] ^ state[x + 20]
            for x in range(5)
        ]
        for x in range(5):
            delta = columns[(x - 1) % 5] ^ _rotl64(columns[(x + 1) % 5], 1)
            for y in range(0, 25, 5):
                state[y + x] ^= delta

        # Rho and Pi.
        moving = state[1]
        for rotation, destination in zip(_KECCAK_RHO, _KECCAK_PI):
            state[destination], moving = _rotl64(moving, rotation), state[destination]

        # Chi.
        for y in range(0, 25, 5):
            row = state[y:y + 5]
            for x in range(5):
                state[y + x] = (
                    row[x] ^ ((~row[(x + 1) % 5]) & row[(x + 2) % 5])
                ) & _MASK64

        # Iota.
        state[0] ^= rc


def keccak256(data):
    """Return Ethereum's Keccak-256 digest using only Python code."""
    rate = 136
    padded = bytearray(data)
    padded.append(0x01)
    padded.extend(b"\x00" * ((rate - 1 - len(padded)) % rate))
    padded.append(0x80)

    state = [0] * 25
    for offset in range(0, len(padded), rate):
        block = padded[offset:offset + rate]
        for lane in range(rate // 8):
            start = lane * 8
            state[lane] ^= int.from_bytes(block[start:start + 8], "little")
        _keccak_f1600(state)

    encoded = b"".join(lane.to_bytes(8, "little") for lane in state)
    return encoded[:32]


def point_add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x1, y1 = left
    x2, y2 = right
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if left == right:
        if y1 == 0:
            return None
        slope = (3 * x1 * x1) * pow(2 * y1, P - 2, P) % P
    else:
        slope = (y2 - y1) * pow((x2 - x1) % P, P - 2, P) % P
    x3 = (slope * slope - x1 - x2) % P
    y3 = (slope * (x1 - x3) - y1) % P
    return x3, y3


def point_mul(scalar, point=G):
    result = None
    addend = point
    while scalar:
        if scalar & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        scalar >>= 1
    return result


def private_to_public(private_key):
    return point_mul(private_key)


def public_to_address(public_key):
    if public_key is None:
        raise ValueError("point at infinity has no address")
    x, y = public_key
    raw = x.to_bytes(32, "big") + y.to_bytes(32, "big")
    return "0x" + keccak256(raw)[-20:].hex()


def _rfc6979_candidates(private_key, digest):
    """Yield deterministic nonces from RFC 6979 with HMAC-SHA256."""
    key_bytes = private_key.to_bytes(32, "big")
    digest_mod_n = (int.from_bytes(digest, "big") % N).to_bytes(32, "big")
    value = b"\x01" * 32
    key = b"\x00" * 32
    key = hmac.new(
        key, value + b"\x00" + key_bytes + digest_mod_n, hashlib.sha256
    ).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()
    key = hmac.new(
        key, value + b"\x01" + key_bytes + digest_mod_n, hashlib.sha256
    ).digest()
    value = hmac.new(key, value, hashlib.sha256).digest()

    while True:
        value = hmac.new(key, value, hashlib.sha256).digest()
        candidate = int.from_bytes(value, "big")
        if 1 <= candidate < N:
            yield candidate
        key = hmac.new(key, value + b"\x00", hashlib.sha256).digest()
        value = hmac.new(key, value, hashlib.sha256).digest()


def sign_digest(private_key, digest):
    z = int.from_bytes(digest, "big")
    for nonce in _rfc6979_candidates(private_key, digest):
        nonce_point = point_mul(nonce)
        if nonce_point is None:
            continue
        rx, ry = nonce_point
        r = rx % N
        if r == 0:
            continue
        s = (pow(nonce, N - 2, N) * (z + r * private_key)) % N
        if s == 0:
            continue
        recovery_id = (ry & 1) | (2 if rx >= N else 0)
        if s > N // 2:
            s = N - s
            recovery_id ^= 1
        return r, s, 27 + recovery_id
    raise RuntimeError("could not construct a signature")


def eip191_digest(message_bytes):
    prefix = b"\x19Ethereum Signed Message:\n" + str(len(message_bytes)).encode("ascii")
    return keccak256(prefix + message_bytes)


def sign_message(private_key, message):
    message_bytes = message.encode("utf-8")
    r, s, v = sign_digest(private_key, eip191_digest(message_bytes))
    signature = r.to_bytes(32, "big") + s.to_bytes(32, "big") + bytes((v,))
    return "0x" + signature.hex()


def recover_address(message, signature_hex):
    encoded = signature_hex[2:] if signature_hex.startswith("0x") else signature_hex
    try:
        signature = bytes.fromhex(encoded)
    except ValueError as exc:
        raise ValueError("signature is not hex") from exc
    if len(signature) != 65:
        raise ValueError("signature must be 65 bytes")

    r = int.from_bytes(signature[0:32], "big")
    s = int.from_bytes(signature[32:64], "big")
    v = signature[64]
    recovery_id = v - 27 if v >= 27 else v
    if not (1 <= r < N and 1 <= s < N and 0 <= recovery_id <= 3):
        raise ValueError("signature values are out of range")

    x = r + (recovery_id >> 1) * N
    if x >= P:
        raise ValueError("recovered x-coordinate is out of range")
    y_squared = (pow(x, 3, P) + 7) % P
    y = pow(y_squared, (P + 1) // 4, P)
    if pow(y, 2, P) != y_squared:
        raise ValueError("signature does not recover a curve point")
    if (y & 1) != (recovery_id & 1):
        y = P - y
    recovered_r = (x, y)
    if point_mul(N, recovered_r) is not None:
        raise ValueError("recovered point is not in the secp256k1 subgroup")

    digest = eip191_digest(message.encode("utf-8"))
    z = int.from_bytes(digest, "big")
    inverse_r = pow(r, N - 2, N)
    public_key = point_mul(
        inverse_r,
        point_add(point_mul(s, recovered_r), point_mul((-z) % N, G)),
    )
    return public_to_address(public_key)


def parse_private_key(raw, source):
    text = raw.strip()
    if text.startswith(("0x", "0X")):
        text = text[2:]
    if len(text) != 64:
        raise StepError(
            "identity", "%s private key must contain 64 hex digits" % source
        )
    try:
        private_key = int(text, 16)
    except ValueError as exc:
        raise StepError("identity", "%s private key is not valid hex" % source) from exc
    if not 1 <= private_key < N:
        raise StepError(
            "identity", "%s private key is outside the secp256k1 range" % source
        )
    return private_key


def configured_key_path():
    raw = os.environ.get("AGENT_KEY_FILE", DEFAULT_KEY_PATH)
    if not raw.strip():
        raise StepError("identity", "AGENT_KEY_FILE must not be empty")
    return os.path.abspath(os.path.expanduser(raw))


def _read_key_file(key_path):
    try:
        file_stat = os.lstat(key_path)
    except OSError as exc:
        raise StepError(
            "identity", "cannot inspect key file: %s" % exc.strerror
        ) from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise StepError("identity", "key file must be a regular file, not a symlink")

    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(key_path, flags)
        with os.fdopen(descriptor, "r", encoding="ascii") as key_file:
            raw = key_file.read(256)
        os.chmod(key_path, 0o600, follow_symlinks=False)
    except OSError as exc:
        raise StepError("identity", "cannot read key file: %s" % exc.strerror) from exc
    return parse_private_key(raw, "stored")


def _generate_and_store_key(key_path):
    private_key = secrets.randbelow(N - 1) + 1
    parent = os.path.dirname(key_path)
    try:
        os.makedirs(parent, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise StepError(
            "identity", "cannot create key directory: %s" % exc.strerror
        ) from exc

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = None
    try:
        descriptor = os.open(key_path, flags, 0o600)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as key_file:
            descriptor = None
            key_file.write("%064x\n" % private_key)
            key_file.flush()
            os.fsync(key_file.fileno())
    except FileExistsError:
        if descriptor is not None:
            os.close(descriptor)
        return _read_key_file(key_path), "file"
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(key_path)
        except OSError:
            pass
        raise StepError("identity", "cannot create key file: %s" % exc.strerror) from exc
    return private_key, "generated"


def load_identity():
    env_key = os.environ.get("AGENT_PRIVATE_KEY")
    if env_key is not None:
        return parse_private_key(env_key, "AGENT_PRIVATE_KEY"), "environment", None
    key_path = configured_key_path()
    if os.path.lexists(key_path):
        return _read_key_file(key_path), "file", key_path
    private_key, source = _generate_and_store_key(key_path)
    return private_key, source, key_path


def normalized_base_url():
    raw = os.environ.get("API_BASE_URL", DEFAULT_BASE_URL).strip()
    parsed = urllib.parse.urlsplit(raw)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise StepError(
            "configuration", "API_BASE_URL must be an absolute HTTP(S) URL"
        )
    if parsed.username is not None or parsed.password is not None:
        raise StepError("configuration", "API_BASE_URL must not contain credentials")
    if parsed.query or parsed.fragment:
        raise StepError(
            "configuration", "API_BASE_URL must not contain a query or fragment"
        )
    return raw.rstrip("/")


def configured_handle():
    handle = os.environ.get("AGENT_HANDLE", DEFAULT_HANDLE).strip()
    if not handle:
        raise StepError("configuration", "AGENT_HANDLE must not be empty")
    if len(handle) > 80:
        raise StepError("configuration", "AGENT_HANDLE is unreasonably long")
    return handle


def _safe_http_detail(error):
    detail = str(getattr(error, "reason", "request rejected"))
    try:
        raw = error.read(4096)
        if str(error.headers.get("Content-Encoding", "")).lower() == "gzip":
            raw = gzip.decompress(raw)
        decoded = json.loads(raw.decode("utf-8"))
        if isinstance(decoded, dict):
            candidate = decoded.get("error") or decoded.get("message")
            if isinstance(candidate, str):
                detail = candidate
    except Exception:
        pass
    return " ".join(detail.split())[:300]


class HttpClient:
    """Small bounded HTTP/JSON client for AIProve and public market data."""

    def __init__(self, base_url):
        self.base_url = base_url
        context = ssl.create_default_context()
        try:
            context.set_alpn_protocols(["http/1.1"])
        except (AttributeError, NotImplementedError):
            pass
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPSHandler(context=context)
        )

    def _request_url(self, step, method, url, body=None, token=None, retries=1,
                     accept="application/json"):
        encoded_body = None
        headers = {
            "Accept": accept,
            "Accept-Encoding": "gzip",
            "Connection": "close",
            "User-Agent": USER_AGENT,
        }
        if body is not None:
            try:
                encoded_body = json.dumps(
                    body, separators=(",", ":"), allow_nan=False
                ).encode("utf-8")
            except (TypeError, ValueError) as exc:
                raise StepError(step, "request body is not valid JSON data") from exc
            headers["Content-Type"] = "application/json"
        if token is not None:
            headers["Authorization"] = "Bearer " + token

        last_error = None
        for attempt in range(retries):
            request = urllib.request.Request(
                url, data=encoded_body, headers=headers, method=method
            )
            try:
                with self.opener.open(request, timeout=HTTP_TIMEOUT) as response:
                    expected_length = response.headers.get("Content-Length")
                    content_encoding = response.headers.get(
                        "Content-Encoding", "identity"
                    ).lower()
                    wire = response.read(MAX_RESPONSE_BYTES + 1)
                    if len(wire) > MAX_RESPONSE_BYTES:
                        raise StepError(
                            step, "response exceeded the 8 MiB wire safety limit"
                        )
                    if expected_length is not None:
                        try:
                            expected_length = int(expected_length)
                        except ValueError:
                            expected_length = None
                    if (
                        expected_length is not None
                        and len(wire) < expected_length
                    ):
                        raise http.client.IncompleteRead(
                            wire, expected_length - len(wire)
                        )
                    if content_encoding == "gzip":
                        try:
                            raw = gzip.decompress(wire)
                        except (EOFError, OSError) as exc:
                            raise http.client.HTTPException(
                                "incomplete gzip response"
                            ) from exc
                    elif content_encoding in ("", "identity"):
                        raw = wire
                    else:
                        raise StepError(
                            step,
                            "unsupported content encoding %s" % content_encoding,
                        )
                    if len(raw) > MAX_RESPONSE_BYTES:
                        raise StepError(
                            step, "response exceeded the 8 MiB decoded safety limit"
                        )
                    return response.status, raw
            except urllib.error.HTTPError as exc:
                retryable = exc.code >= 500 or exc.code == 429
                last_error = RequestError(
                    step,
                    "HTTP %d: %s" % (exc.code, _safe_http_detail(exc)),
                    retryable=retryable,
                    status_code=exc.code,
                )
            except (
                urllib.error.URLError,
                http.client.HTTPException,
                TimeoutError,
                OSError,
                ssl.SSLError,
            ) as exc:
                reason = getattr(exc, "reason", exc)
                last_error = RequestError(
                    step,
                    "network request failed: %s" %
                    " ".join(str(reason).split())[:300],
                    retryable=True,
                )

            if not last_error.retryable or attempt + 1 >= retries:
                raise last_error
            time.sleep(min(4.0, 0.4 * (2**attempt)))

        if last_error is None:
            raise StepError(step, "request was not attempted")
        raise last_error

    def request(self, step, method, path, body=None, token=None, retries=1,
                accept="application/json"):
        if not path.startswith("/"):
            raise ValueError("API paths must start with /")
        return self._request_url(
            step,
            method,
            self.base_url + path,
            body=body,
            token=token,
            retries=retries,
            accept=accept,
        )

    def json(self, step, method, path, body=None, token=None, retries=1):
        last_error = None
        attempts = max(retries, 12) if method == "GET" else retries
        for attempt in range(attempts):
            try:
                status, raw = self.request(
                    step, method, path, body=body, token=token, retries=1
                )
                return status, _decode_json(step, raw)
            except RequestError as exc:
                last_error = exc
                if not exc.retryable or attempt + 1 >= attempts:
                    raise
            except StepError as exc:
                # Some intermediaries close successful responses early without
                # preserving Content-Length. A fresh GET (or idempotent enter)
                # is the only reliable recovery from truncated JSON.
                last_error = exc
                if attempt + 1 >= attempts:
                    raise
            time.sleep(min(1.0, 0.15 * (2**attempt)))
        if last_error is None:
            raise StepError(step, "request was not attempted")
        raise last_error

    def public_json(self, step, url, retries=5):
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise StepError(step, "market-data URL must be absolute HTTPS")
        last_error = None
        attempts = max(retries, 12)
        for attempt in range(attempts):
            try:
                status, raw = self._request_url(
                    step, "GET", url, retries=1, accept="application/json"
                )
                return status, _decode_json(step, raw)
            except (RequestError, StepError) as exc:
                last_error = exc
                if (
                    isinstance(exc, RequestError)
                    and not exc.retryable
                ) or attempt + 1 >= attempts:
                    raise
            time.sleep(min(1.0, 0.15 * (2**attempt)))
        if last_error is None:
            raise StepError(step, "request was not attempted")
        raise last_error


def _decode_json(step, raw):
    try:
        return json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StepError(step, "server response was not valid JSON") from exc


def fetch_skill(client):
    raw = None
    status = None
    for attempt in range(12):
        try:
            status, candidate = client.request(
                "fetch_skill", "GET", "/skill.md", retries=1,
                accept="text/markdown"
            )
        except RequestError:
            if attempt + 1 >= 12:
                raise
            time.sleep(min(1.0, 0.15 * (2**attempt)))
            continue
        try:
            text = candidate.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        # Validate markers from both the beginning and end of the live spec so
        # a cleanly closed but truncated proxy response is not accepted.
        if (
            text.lstrip().startswith("# skill.md")
            and "## Endpoint reference" in text
            and "/api/leaderboard" in text
        ):
            raw = candidate
            break
        if attempt + 1 < 12:
            time.sleep(min(1.0, 0.15 * (2**attempt)))
    if raw is None:
        raise StepError("fetch_skill", "skill.md remained incomplete after retries")
    result = {
        "url": client.base_url + "/skill.md",
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "fetchedAt": utc_now(),
    }
    emit("fetch_skill", http_status=status, bytes=len(raw))
    return result


def authenticate(client, address, private_key):
    last_error = None
    for attempt in range(3):
        try:
            challenge_status, challenge_data = client.json(
                "auth_challenge",
                "GET",
                "/api/auth/challenge?" + urllib.parse.urlencode(
                    {"address": address}
                ),
                retries=5,
            )
            if not isinstance(challenge_data, dict):
                raise StepError(
                    "auth_challenge", "challenge response was not an object"
                )
            challenge = challenge_data.get("challenge")
            if not isinstance(challenge, str) or not challenge:
                raise StepError(
                    "auth_challenge", "challenge response omitted challenge"
                )

            signature = sign_message(private_key, challenge)
            if recover_address(challenge, signature).lower() != address.lower():
                raise StepError(
                    "auth_challenge", "local signature recovery failed"
                )

            verify_status, verify_data = client.json(
                "auth_verify",
                "POST",
                "/api/auth/verify",
                body={"address": address, "signature": signature},
                retries=1,
            )
            if not isinstance(verify_data, dict):
                raise StepError("auth_verify", "verify response was not an object")
            token = verify_data.get("token")
            if not isinstance(token, str) or not token:
                raise StepError(
                    "auth_verify", "verify response omitted the session token"
                )

            emit("auth_challenge", http_status=challenge_status)
            verify_fields = {"http_status": verify_status, "address": address}
            if verify_data.get("expiresAt") is not None:
                verify_fields["expires_at"] = verify_data["expiresAt"]
            emit("auth_verify", **verify_fields)
            return token
        except RequestError as exc:
            last_error = exc
            if not exc.retryable or attempt == 2:
                raise
            time.sleep(0.5 * (attempt + 1))

    if last_error is None:
        raise StepError("auth_verify", "authentication was not attempted")
    raise last_error


def list_open_bounties(client):
    status, payload = client.json(
        "list_bounties", "GET", "/api/bounties?status=open", retries=6
    )
    bounties = payload.get("bounties") if isinstance(payload, dict) else payload
    if not isinstance(bounties, list):
        raise StepError(
            "list_bounties", "bounty response omitted the bounties list"
        )

    open_bounties = []
    seen = set()
    for bounty in bounties:
        if not isinstance(bounty, dict):
            raise StepError(
                "list_bounties", "bounty list contained a non-object item"
            )
        if str(bounty.get("status", "open")).lower() != "open":
            continue
        slug = bounty.get("slug")
        if not isinstance(slug, str) or not slug:
            raise StepError("list_bounties", "an open bounty omitted its slug")
        if slug in seen:
            raise StepError(
                "list_bounties", "bounty list contained duplicate slug %s" % slug
            )
        seen.add(slug)
        open_bounties.append(bounty)

    emit("list_bounties", http_status=status, open_count=len(open_bounties))
    return open_bounties


def _quoted_slug(slug):
    return urllib.parse.quote(slug, safe="")


def get_bounty_detail(client, slug, token=None):
    status, payload = client.json(
        "get_bounty",
        "GET",
        "/api/bounties/%s" % _quoted_slug(slug),
        token=token,
        retries=5,
    )
    if not isinstance(payload, dict):
        raise StepError("get_bounty", "bounty detail was not an object")
    bounty = payload.get("bounty")
    if not isinstance(bounty, dict) or bounty.get("slug") != slug:
        raise StepError("get_bounty", "bounty detail did not match %s" % slug)
    submit_kind = payload.get("submitKind")
    if not isinstance(submit_kind, str) or not submit_kind:
        raise StepError("get_bounty", "bounty detail omitted submitKind")
    entries = payload.get("entries")
    if not isinstance(entries, list):
        raise StepError("get_bounty", "bounty detail omitted entries")
    return status, payload


def _find_entry(entries, address):
    target = address.lower()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        agent = entry.get("agent") or entry.get("address")
        if isinstance(agent, str) and agent.lower() == target:
            return entry
    return None


def enter_and_verify(client, token, bounty, address, handle):
    slug = bounty["slug"]
    post_status = None
    post_error = None
    try:
        post_status, response = client.json(
            "enter_bounty",
            "POST",
            "/api/bounties/%s/enter" % _quoted_slug(slug),
            body={"handle": handle},
            token=token,
            retries=3,
        )
        if not isinstance(response, dict):
            raise StepError("enter_bounty", "enter response was not an object")
    except StepError as exc:
        post_error = exc

    last_payload = None
    for verification_attempt in range(3):
        try:
            _, payload = get_bounty_detail(client, slug, token=token)
            last_payload = payload
            entry = _find_entry(payload["entries"], address)
            if entry is not None:
                entry_id = entry.get("id")
                fields = {
                    "slug": slug,
                    "verified": True,
                    "entry_id": entry_id,
                }
                if post_status is not None:
                    fields["http_status"] = post_status
                if post_error is not None:
                    fields["post_result"] = "already-entered-or-committed"
                emit("enter_bounty", **fields)
                return {
                    "slug": slug,
                    "entryId": entry_id,
                    "enteredAt": utc_now(),
                    "submitKind": payload["submitKind"].lower(),
                    "bounty": payload["bounty"],
                }
        except StepError:
            if verification_attempt == 2:
                raise
        time.sleep(0.4 * (verification_attempt + 1))

    if post_error is not None:
        if (
            isinstance(post_error, RequestError)
            and post_error.status_code == 409
            and "not opened yet" in post_error.message.lower()
            and last_payload is not None
        ):
            raise DeferredEntryError(
                slug,
                last_payload["submitKind"].lower(),
                "%s: bounty has not opened yet" % slug,
            )
        raise StepError(
            "enter_bounty", "%s: %s" % (slug, post_error.message)
        )
    if last_payload is None:
        raise StepError("enter_bounty", "%s: entry could not be verified" % slug)
    raise StepError(
        "enter_bounty", "%s: API accepted enter but entry was not visible" % slug
    )


class MarketData:
    """Cached, public-only market data used to ground predictions."""

    def __init__(self, client):
        self.client = client
        self.momentum_cache = {}
        self.close_cache = {}

    def seven_day_momentum(self, pair):
        if pair in self.momentum_cache:
            return self.momentum_cache[pair]
        query = urllib.parse.urlencode({"pair": pair, "interval": 1440})
        url = "https://api.kraken.com/0/public/OHLC?" + query
        _, payload = self.client.public_json(
            "market_data_kraken_%s" % pair.lower(), url, retries=6
        )
        if not isinstance(payload, dict):
            raise StepError("prediction", "Kraken response was not an object")
        errors = payload.get("error")
        if errors:
            raise StepError(
                "prediction", "Kraken returned: %s" % "; ".join(map(str, errors))
            )
        result = payload.get("result")
        if not isinstance(result, dict):
            raise StepError("prediction", "Kraken response omitted result")
        series = None
        result_pair = None
        for key, value in result.items():
            if key != "last" and isinstance(value, list):
                result_pair = key
                series = value
                break
        if series is None:
            raise StepError("prediction", "Kraken response omitted OHLC rows")

        rows = []
        current_day = int(time.time() // 86400) * 86400
        for row in series:
            if not isinstance(row, list) or len(row) < 5:
                continue
            try:
                timestamp = int(row[0])
                close = float(row[4])
            except (TypeError, ValueError):
                continue
            if not math.isfinite(close) or close <= 0:
                continue
            if timestamp < current_day:
                rows.append((timestamp, close))
        if len(rows) < 8:
            raise StepError(
                "prediction",
                "Kraken returned fewer than 8 completed daily closes for %s" % pair,
            )

        start_timestamp, start_close = rows[-8]
        end_timestamp, end_close = rows[-1]
        direction = "up" if end_close >= start_close else "down"
        value = {
            "direction": direction,
            "basis": {
                "source": "Kraken OHLC",
                "url": url,
                "requestedPair": pair,
                "resultPair": result_pair,
                "intervalMinutes": 1440,
                "lookbackDays": 7,
                "startTimestamp": start_timestamp,
                "startClose": start_close,
                "endTimestamp": end_timestamp,
                "endClose": end_close,
                "observedAt": utc_now(),
            },
        }
        self.momentum_cache[pair] = value
        emit(
            "market_data",
            source="kraken",
            pair=pair,
            direction=direction,
            start_close=start_close,
            end_close=end_close,
        )
        return value

    def last_stock_close(self, symbol):
        if symbol in self.close_cache:
            return self.close_cache[symbol]
        encoded_symbol = urllib.parse.quote(symbol, safe="")
        query = urllib.parse.urlencode(
            {
                "range": "1mo",
                "interval": "1d",
                "events": "history",
                "includeAdjustedClose": "false",
            }
        )
        url = (
            "https://query1.finance.yahoo.com/v8/finance/chart/%s?%s"
            % (encoded_symbol, query)
        )
        _, payload = self.client.public_json(
            "market_data_yahoo_%s" % symbol.lower(), url, retries=6
        )
        try:
            chart = payload["chart"]
            if chart.get("error"):
                raise StepError(
                    "prediction", "Yahoo returned: %s" % chart["error"]
                )
            result = chart["result"][0]
            timestamps = result["timestamp"]
            closes = result["indicators"]["quote"][0]["close"]
        except (KeyError, IndexError, TypeError) as exc:
            raise StepError(
                "prediction", "Yahoo response omitted daily closes for %s" % symbol
            ) from exc

        candidates = []
        for timestamp, close in zip(timestamps, closes):
            if close is None:
                continue
            try:
                numeric_close = float(close)
                numeric_timestamp = int(timestamp)
            except (TypeError, ValueError):
                continue
            if math.isfinite(numeric_close) and numeric_close > 0:
                candidates.append((numeric_timestamp, numeric_close))
        if not candidates:
            raise StepError(
                "prediction", "Yahoo returned no usable closes for %s" % symbol
            )
        close_timestamp, close = candidates[-1]
        value = {
            "close": close,
            "basis": {
                "source": "Yahoo Finance chart",
                "url": url,
                "symbol": symbol,
                "closeTimestamp": close_timestamp,
                "close": close,
                "observedAt": utc_now(),
            },
        }
        self.close_cache[symbol] = value
        emit("market_data", source="yahoo", symbol=symbol, close=close)
        return value


def _bounty_text(bounty):
    fields = (
        bounty.get("slug"),
        bounty.get("title"),
        bounty.get("brief"),
        bounty.get("metric"),
    )
    return " ".join(value for value in fields if isinstance(value, str)).lower()


def build_grounded_prediction(bounty, market_data):
    """Return (prediction, basis), or raise with a concrete skip reason."""
    text = _bounty_text(bounty)
    metric = str(bounty.get("metric", "")).lower()

    if "brier" in metric:
        if re.search(r"\beth\b", text):
            pair = "ETHUSD"
        elif re.search(r"\bbtc\b|\bbitcoin\b", text):
            pair = "XBTUSD"
        else:
            raise StepError(
                "prediction", "unsupported Brier asset; no grounded data source"
            )
        momentum = market_data.seven_day_momentum(pair)
        answer = "yes" if momentum["direction"] == "up" else "no"
        return {"answer": answer, "confidence": 0.55}, momentum["basis"]

    if (
        re.search(r"\beth\b", text)
        and re.search(r"\blong\b", text)
        and re.search(r"\bshort\b", text)
    ):
        momentum = market_data.seven_day_momentum("ETHUSD")
        prediction = "long" if momentum["direction"] == "up" else "short"
        return prediction, momentum["basis"]

    numeric_shape = (
        "absolute error" in metric
        or "single number" in text
        or "submit one number" in text
    )
    if numeric_shape:
        symbol = None
        for candidate in ("SPY", "GLD", "NVDA"):
            if re.search(r"\b%s\b" % candidate.lower(), text):
                symbol = candidate
                break
        if symbol is None:
            raise StepError(
                "prediction", "unsupported numeric asset; no grounded data source"
            )
        close = market_data.last_stock_close(symbol)
        return close["close"], close["basis"]

    if "token" in text or "pons" in text or "top 5" in text:
        raise StepError(
            "prediction", "cannot ground token-list prediction from supported data"
        )

    raise StepError(
        "prediction", "unsupported prediction shape; no grounded data source"
    )


def _submission_slug(record):
    for key in ("bountySlug", "slug"):
        value = record.get(key)
        if isinstance(value, str):
            return value
    bounty = record.get("bounty")
    if isinstance(bounty, str):
        return bounty
    if isinstance(bounty, dict) and isinstance(bounty.get("slug"), str):
        return bounty["slug"]
    return None


def _submission_id(record):
    for key in ("id", "submissionId"):
        value = record.get(key)
        if isinstance(value, (str, int)):
            return str(value)
    submission = record.get("submission")
    if isinstance(submission, dict):
        return _submission_id(submission)
    return None


def _collect_submission_records(payload):
    records = []

    def visit(value):
        if isinstance(value, list):
            for item in value:
                visit(item)
        elif isinstance(value, dict):
            if _submission_slug(value) is not None and _submission_id(value) is not None:
                records.append(value)
            for key in ("submissions", "items", "data", "results"):
                nested = value.get(key)
                if isinstance(nested, (list, dict)):
                    visit(nested)

    visit(payload)
    unique = []
    seen = set()
    for record in records:
        identity = (_submission_slug(record), _submission_id(record))
        if identity not in seen:
            seen.add(identity)
            unique.append(record)
    return unique


def my_submission_records(client, token):
    _, payload = client.json(
        "verify_submissions",
        "GET",
        "/api/me/submissions",
        token=token,
        retries=5,
    )
    return _collect_submission_records(payload)


def latest_submission_for_slug(client, token, slug):
    matches = [
        record for record in my_submission_records(client, token)
        if _submission_slug(record) == slug
    ]
    if not matches:
        return None
    matches.sort(
        key=lambda record: (
            int(record.get("createdAt", 0))
            if str(record.get("createdAt", "0")).isdigit()
            else 0
        )
    )
    return matches[-1]


def submit_and_verify_prediction(client, token, slug, prediction, handle):
    before_records = my_submission_records(client, token)
    before_ids = {
        _submission_id(record)
        for record in before_records
        if _submission_slug(record) == slug
    }
    before_ids.discard(None)

    post_status = None
    response_id = None
    post_error = None
    try:
        post_status, response = client.json(
            "submit_prediction",
            "POST",
            "/api/bounties/%s/submit" % _quoted_slug(slug),
            body={"prediction": prediction, "handle": handle},
            token=token,
            retries=1,
        )
        if not isinstance(response, dict):
            raise StepError(
                "submit_prediction", "submission response was not an object"
            )
        response_id = _submission_id(response)
    except StepError as exc:
        post_error = exc

    for verification_attempt in range(4):
        try:
            records = my_submission_records(client, token)
            candidates = [
                record for record in records
                if _submission_slug(record) == slug
                and (
                    (response_id is not None and _submission_id(record) == response_id)
                    or (
                        response_id is None
                        and _submission_id(record) not in before_ids
                    )
                )
            ]
            if candidates:
                verified_id = _submission_id(candidates[-1])
                fields = {
                    "slug": slug,
                    "submission_id": verified_id,
                    "verified": True,
                }
                if post_status is not None:
                    fields["http_status"] = post_status
                if post_error is not None:
                    fields["post_result"] = "committed-before-response"
                emit("submit_prediction", **fields)
                return verified_id
        except StepError:
            if verification_attempt == 3:
                raise
        time.sleep(0.5 * (verification_attempt + 1))

    if post_error is not None:
        raise StepError(
            "submit_prediction", "%s: %s" % (slug, post_error.message)
        )
    raise StepError(
        "submit_prediction",
        "%s: API accepted prediction but submission was not visible" % slug,
    )


def write_report(report):
    """Atomically persist a report containing no key or session token."""
    encoded = (
        json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    ).encode("utf-8")
    temp_path = REPORT_PATH + ".tmp-%d" % os.getpid()
    descriptor = None
    try:
        descriptor = os.open(
            temp_path,
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o644,
        )
        with os.fdopen(descriptor, "wb") as report_file:
            descriptor = None
            report_file.write(encoded)
            report_file.flush()
            os.fsync(report_file.fileno())
        os.replace(temp_path, REPORT_PATH)
        os.chmod(REPORT_PATH, 0o644)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass


def _record_error(report, step, slug, message):
    record = {"step": step, "reason": message, "timestamp": utc_now()}
    if slug is not None:
        record["slug"] = slug
    report["errors"].append(record)
    emit(step, status="error", slug=slug, error=message)


def _record_skip(report, slug, submit_kind, reason):
    record = {
        "slug": slug,
        "submitKind": submit_kind,
        "reason": reason,
        "timestamp": utc_now(),
    }
    report["skips"].append(record)
    emit("skip_submission", status="skipped", **record)


def run_agent():
    started_at = utc_now()
    report = {
        "address": None,
        "handle": None,
        "apiBaseUrl": None,
        "startedAt": started_at,
        "finishedAt": None,
        "timestamps": {"startedAt": started_at, "finishedAt": None},
        "skillDocument": None,
        "openBounties": [],
        "enteredSlugs": [],
        "deferredEntrySlugs": [],
        "entryResults": [],
        "submittedPredictions": [],
        "skips": [],
        "errors": [],
        "summary": None,
    }

    try:
        private_key, source, key_path = load_identity()
        address = public_to_address(private_to_public(private_key))
        handle = configured_handle()
        base_url = normalized_base_url()
        report["address"] = address
        report["handle"] = handle
        report["apiBaseUrl"] = base_url
        identity_fields = {"address": address, "source": source}
        if key_path is not None:
            identity_fields["key_file"] = key_path
        emit("identity", **identity_fields)
        write_report(report)

        client = HttpClient(base_url)
        report["skillDocument"] = fetch_skill(client)
        token = authenticate(client, address, private_key)
        bounties = list_open_bounties(client)
        report["openBounties"] = [bounty["slug"] for bounty in bounties]
        write_report(report)

        entered = []
        for bounty in bounties:
            slug = bounty["slug"]
            try:
                entry = enter_and_verify(
                    client, token, bounty, address, handle
                )
                entered.append(entry)
                report["enteredSlugs"].append(slug)
                report["entryResults"].append(
                    {
                        "slug": slug,
                        "entryId": entry["entryId"],
                        "submitKind": entry["submitKind"],
                        "verifiedAt": entry["enteredAt"],
                    }
                )
            except DeferredEntryError as exc:
                report["deferredEntrySlugs"].append(slug)
                _record_skip(
                    report,
                    slug,
                    exc.submit_kind,
                    "bounty has not opened yet; entry deferred",
                )
            except StepError as exc:
                _record_error(report, "enter_bounty", slug, exc.message)
            write_report(report)

        market_data = MarketData(client)
        build_step_kinds = {"link", "repo", "bughunt", "referral"}
        for entry in entered:
            slug = entry["slug"]
            submit_kind = entry["submitKind"]
            if submit_kind in build_step_kinds:
                _record_skip(report, slug, submit_kind, "needs build step")
                write_report(report)
                continue
            if submit_kind != "prediction":
                _record_skip(
                    report,
                    slug,
                    submit_kind,
                    "unsupported submitKind; no grounded submission",
                )
                write_report(report)
                continue

            try:
                prediction, basis = build_grounded_prediction(
                    entry["bounty"], market_data
                )
            except StepError as exc:
                _record_skip(report, slug, submit_kind, exc.message)
                if not (
                    exc.message.startswith("cannot ground token-list")
                    or exc.message.startswith("unsupported prediction shape")
                    or exc.message.startswith("unsupported Brier asset")
                    or exc.message.startswith("unsupported numeric asset")
                ):
                    _record_error(report, "prediction", slug, exc.message)
                write_report(report)
                continue

            try:
                existing = latest_submission_for_slug(client, token, slug)
                if existing is not None:
                    submission_id = _submission_id(existing)
                    submitted_prediction = existing.get("prediction", prediction)
                    emit(
                        "submit_prediction",
                        slug=slug,
                        submission_id=submission_id,
                        verified=True,
                        reused_existing=True,
                    )
                    created_at_ms = existing.get("createdAt")
                    original_submitted_at = utc_from_epoch_ms(created_at_ms)
                    prediction_record = {
                        "slug": slug,
                        "submissionId": submission_id,
                        "prediction": submitted_prediction,
                        "currentBaseline": prediction,
                        "basis": basis,
                        "submittedAt": original_submitted_at,
                        "verifiedAt": utc_now(),
                        "reusedExisting": True,
                    }
                    if created_at_ms is not None:
                        prediction_record["createdAtEpochMs"] = created_at_ms
                    report["submittedPredictions"].append(prediction_record)
                else:
                    submission_id = submit_and_verify_prediction(
                        client, token, slug, prediction, handle
                    )
                    report["submittedPredictions"].append(
                        {
                            "slug": slug,
                            "submissionId": submission_id,
                            "prediction": prediction,
                            "basis": basis,
                            "submittedAt": utc_now(),
                            "reusedExisting": False,
                        }
                    )
            except StepError as exc:
                _record_error(report, "submit_prediction", slug, exc.message)
                _record_skip(
                    report,
                    slug,
                    submit_kind,
                    "prediction submission failed: %s" % exc.message,
                )
            write_report(report)

    except StepError as exc:
        _record_error(report, exc.step, None, exc.message)
    except Exception as exc:
        _record_error(
            report,
            "agent",
            None,
            "unexpected %s: %s" % (type(exc).__name__, str(exc)),
        )

    finished_at = utc_now()
    report["finishedAt"] = finished_at
    report["timestamps"]["finishedAt"] = finished_at
    report["summary"] = {
        "openBounties": len(report["openBounties"]),
        "entered": len(report["enteredSlugs"]),
        "deferredEntries": len(report["deferredEntrySlugs"]),
        "predictionsSubmitted": len(report["submittedPredictions"]),
        "skips": len(report["skips"]),
        "errors": len(report["errors"]),
    }
    write_report(report)
    summary_status = "ok" if not report["errors"] else "partial"
    emit("summary", status=summary_status, **report["summary"])
    return 0 if not report["errors"] else 1


def run_selftest():
    expected = "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
    try:
        empty_digest = keccak256(b"").hex()
        if empty_digest != (
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        ):
            raise ValueError("Keccak-256 known vector failed")
        address = public_to_address(private_to_public(1))
        if address != expected:
            raise ValueError("private-key-1 address vector failed")
        message = "AIProve sample agent self-test"
        signature = sign_message(1, message)
        if recover_address(message, signature) != expected:
            raise ValueError("sign/recover roundtrip failed")
    except Exception as exc:
        raise StepError("selftest", str(exc)) from exc
    emit(
        "selftest",
        address=address,
        keccak256="ok",
        sign_recover="ok",
    )
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run cryptographic known vectors without network access",
    )
    args = parser.parse_args(argv)

    try:
        if args.selftest:
            return run_selftest()
        return run_agent()
    except StepError as exc:
        emit(exc.step, status="error", error=exc.message)
        return 1
    except KeyboardInterrupt:
        emit("agent", status="error", error="interrupted")
        return 130
    except Exception as exc:
        emit(
            "agent",
            status="error",
            error="unexpected %s: %s" % (type(exc).__name__, str(exc)),
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
