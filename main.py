from __future__ import annotations

import imaplib
import ssl
import socket
import time
import re
from typing import Optional, Tuple
from urllib.parse import urlparse

import socks  # PySocks
from fastapi import FastAPI, Query, HTTPException, Request
from pydantic import BaseModel

app = FastAPI(title="IMAP Login Checker", version="1.3.0")

# --- Konfigurasi dasar ---
DEFAULT_TIMEOUT_SECONDS = 12
DEFAULT_IMAP_PORT = 993
MAX_GREETING_LEN = 160

# Allowlist domain -> host mapping
DOMAIN_IMAP_MAP: dict[str, Tuple[str, int]] = {
    # Google
    "gmail.com": ("imap.gmail.com", 993),
    "googlemail.com": ("imap.gmail.com", 993),

    # Yahoo
    "yahoo.com": ("imap.mail.yahoo.com", 993),
    "ymail.com": ("imap.mail.yahoo.com", 993),
    "rocketmail.com": ("imap.mail.yahoo.com", 993),

    # Microsoft (personal)
    "outlook.com": ("imap-mail.outlook.com", 993),
    "hotmail.com": ("imap-mail.outlook.com", 993),
    "live.com": ("imap-mail.outlook.com", 993),
    "msn.com": ("imap-mail.outlook.com", 993),

    # Microsoft 365 (work/school)
    "office365.com": ("outlook.office365.com", 993),
    "microsoft.com": ("outlook.office365.com", 993),

    # Apple iCloud
    "icloud.com": ("imap.mail.me.com", 993),
    "me.com": ("imap.mail.me.com", 993),
    "mac.com": ("imap.mail.me.com", 993),

    # Proton
    "proton.me": ("imap.proton.me", 993),
    "protonmail.com": ("imap.proton.me", 993),

    # Zoho
    "zoho.com": ("imap.zoho.com", 993),

    # GMX / Mail.com / Fastmail
    "gmx.com": ("imap.gmx.com", 993),
    "mail.com": ("imap.mail.com", 993),
    "fastmail.com": ("imap.fastmail.com", 993),

    # AOL
    "aol.com": ("imap.aol.com", 993),

    # Yandex
    "yandex.com": ("imap.yandex.com", 993),
    "yandex.ru": ("imap.yandex.ru", 993),

    # Naver
    "naver.com": ("imap.naver.com", 993),

    # Mail.ru
    "mail.ru": ("imap.mail.ru", 993),

    # SoftBank (Japan)
    "i.softbank.jp": ("imap.softbank.jp", 993),
    "softbank.ne.jp": ("imap.softbank.jp", 993),

    # SoftBank corporate (likely Microsoft 365)
    "softbank.com": ("outlook.office365.com", 993),
}

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Rate-limit sederhana per IP
RATE_LIMIT_BUCKET: dict[str, list[float]] = {}
RL_MAX = 5
RL_WINDOW = 60.0


class ImapCheckResponse(BaseModel):
    status: str                   # "ok"|"error"
    imap: str | None              # imaps://host:port/INBOX
    login: str                    # "valid"|"invalid"
    latency_ms: int | None = None
    server_greeting: str | None = None
    error: str | None = None
    proxy_used: str | None = None # e.g. "socks5://host:port"


def _rate_limit_ok(ip: str) -> bool:
    now = time.time()
    bucket = RATE_LIMIT_BUCKET.setdefault(ip, [])
    RATE_LIMIT_BUCKET[ip] = [t for t in bucket if now - t <= RL_WINDOW]
    if len(RATE_LIMIT_BUCKET[ip]) >= RL_MAX:
        return False
    RATE_LIMIT_BUCKET[ip].append(now)
    return True


def _resolve_imap_host(user: str, host: Optional[str], port: Optional[int]) -> Tuple[str, int]:
    if host:
        return host, port or DEFAULT_IMAP_PORT
    domain = user.split("@")[-1].lower()
    pair = DOMAIN_IMAP_MAP.get(domain)
    if not pair:
        raise HTTPException(
            status_code=400,
            detail="Unknown IMAP host for this domain. Provide ?host=imap.example.com explicitly.",
        )
    return pair


@app.get("/providers")
async def list_providers():
    return {"providers": sorted(DOMAIN_IMAP_MAP.keys())}


@app.get("/testlogin/imap", response_model=ImapCheckResponse)
async def test_login(
    request: Request,
    auth: str = Query(..., description="Format: user@domain|password"),
    host: Optional[str] = Query(None, description="IMAP host (required if domain not in allowlist)"),
    port: Optional[int] = Query(None, description="IMAP port; default 993"),
    timeout: Optional[int] = Query(None, description="Socket timeout seconds; default 12"),
    proxy: Optional[str] = Query(
        None,
        description="Optional proxy URL (socks5://user:pass@host:port | socks4://host:port | http://host:port)",
    ),
):
    client_ip = request.client.host if request.client else "unknown"
    if not _rate_limit_ok(client_ip):
        raise HTTPException(status_code=429, detail="Too many requests; slow down.")

    if "|" not in auth:
        raise HTTPException(status_code=400, detail="Invalid auth format. Use user@domain|password")
    user, password = auth.split("|", 1)

    if not EMAIL_RE.match(user):
        raise HTTPException(status_code=400, detail="Invalid email format.")

    try:
        imap_host, imap_port = _resolve_imap_host(user, host, port)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Timeout & TLS
    socket.setdefaulttimeout(float(timeout or DEFAULT_TIMEOUT_SECONDS))
    context = ssl.create_default_context()
    tls_min = (request.query_params.get("tls_min") or "").strip()
    if tls_min == "1.2":
        try:
            context.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass

    # Optional proxy via PySocks (monkey-patch create_connection sementara)
    proxy_display: Optional[str] = None
    original_create_connection = socket.create_connection

    def _create_connection_via_proxy(address, timeout=None, source_address=None):
        host_, port_ = address
        s = socks.socksocket()
        if timeout is not None:
            s.settimeout(timeout)
        if source_address:
            s.bind(source_address)
        s.set_proxy(
            proxy_cfg["type"],
            proxy_cfg["host"],
            proxy_cfg["port"],
            True,
            proxy_cfg.get("username"),
            proxy_cfg.get("password"),
        )
        s.connect((host_, port_))
        return s

    proxy_cfg = None
    if proxy:
        try:
            url = urlparse(proxy)
            scheme = (url.scheme or "").lower()
            if scheme not in {"socks5", "socks4", "http"}:
                raise ValueError("Unsupported proxy scheme (use socks5, socks4, or http)")
            proxy_type = {"socks5": socks.SOCKS5, "socks4": socks.SOCKS4, "http": socks.HTTP}[scheme]
            proxy_cfg = {
                "type": proxy_type,
                "host": url.hostname,
                "port": url.port or (1080 if scheme.startswith("socks") else 8080),
                "username": url.username,
                "password": url.password,
            }
            if not proxy_cfg["host"]:
                raise ValueError("Proxy host missing")
            proxy_display = f"{scheme}://{proxy_cfg['host']}:{proxy_cfg['port']}"
            socket.create_connection = _create_connection_via_proxy
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Invalid proxy: {e}")

    start = time.perf_counter()
    greeting: Optional[str] = None
    try:
        conn = imaplib.IMAP4_SSL(host=imap_host, port=imap_port, ssl_context=context)
        if conn.welcome:
            try:
                greeting = conn.welcome.decode("utf-8", "ignore")
            except Exception:
                greeting = str(conn.welcome)

        typ, _ = conn.login(user, password)
        success = (typ == "OK")

        if success:
            try:
                conn.select("INBOX", readonly=True)
            except Exception:
                pass
            try:
                conn.logout()
            except Exception:
                pass
            latency_ms = int((time.perf_counter() - start) * 1000)
            return ImapCheckResponse(
                status="ok",
                imap=f"imaps://{imap_host}:{imap_port}/INBOX",
                login="valid",
                latency_ms=latency_ms,
                server_greeting=(greeting[:MAX_GREETING_LEN] if greeting else None),
                error=None,
                proxy_used=proxy_display,
            )

        # typ != OK
        try:
            conn.logout()
        except Exception:
            pass
        latency_ms = int((time.perf_counter() - start) * 1000)
        return ImapCheckResponse(
            status="ok",
            imap=f"imaps://{imap_host}:{imap_port}/INBOX",
            login="invalid",
            latency_ms=latency_ms,
            server_greeting=(greeting[:MAX_GREETING_LEN] if greeting else None),
            error=None,
            proxy_used=proxy_display,
        )

    except imaplib.IMAP4.error as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        msg = str(e)
        auth_failed = any(
            k in msg.lower() for k in ["authenticationfailed", "invalid credentials", "login failed"]
        )
        return ImapCheckResponse(
            status="ok" if auth_failed else "error",
            imap=f"imaps://{imap_host}:{imap_port}/INBOX",
            login="invalid",
            latency_ms=latency_ms,
            server_greeting=(greeting[:MAX_GREETING_LEN] if greeting else None),
            error=None if auth_failed else msg,
            proxy_used=proxy_display,
        )
    except (ssl.SSLError, socket.timeout, ConnectionError) as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return ImapCheckResponse(
            status="error",
            imap=f"imaps://{imap_host}:{imap_port}/INBOX",
            login="invalid",
            latency_ms=latency_ms,
            server_greeting=(greeting[:MAX_GREETING_LEN] if greeting else None),
            error=str(e),
            proxy_used=proxy_display,
        )
    except Exception as e:
        latency_ms = int((time.perf_counter() - start) * 1000)
        return ImapCheckResponse(
            status="error",
            imap=f"imaps://{imap_host}:{imap_port}/INBOX",
            login="invalid",
            latency_ms=latency_ms,
            server_greeting=(greeting[:MAX_GREETING_LEN] if greeting else None),
            error=str(e),
            proxy_used=proxy_display,
        )
    finally:
        # Pastikan selalu restore koneksi asli
        socket.create_connection = original_create_connection
