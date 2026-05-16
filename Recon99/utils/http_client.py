"""
utils/http_client.py
Recon99 — Shared requests session with retry, stealth UA, and timeout
Author: FMShomit
"""

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

RECON99_UA = "Recon99/1.0 (+https://github.com/FMShomit/Recon99)"


def build_session(
    timeout: int = 10,
    user_agent: str = DEFAULT_UA,
    retries: int = 2,
    verify_ssl: bool = False,
) -> requests.Session:
    """
    Build and return a requests.Session with:
    - Connection/read retry with backoff
    - Custom User-Agent
    - SSL verification disabled (pentesting context)
    - Reasonable timeouts
    """
    session = requests.Session()

    retry = Retry(
        total=retries,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "HEAD", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://",  adapter)

    session.headers.update({
        "User-Agent": user_agent,
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Connection": "keep-alive",
    })

    # Suppress SSL warnings in pentesting context
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session.verify = verify_ssl
    session.timeout = timeout   # stored for use in module code

    return session


def safe_get(session: requests.Session, url: str, timeout: int = 10, **kwargs):
    """Perform a GET request; return (response | None, error_str | None)."""
    try:
        resp = session.get(url, timeout=timeout, allow_redirects=True, **kwargs)
        return resp, None
    except requests.exceptions.SSLError:
        # Retry over HTTP
        try:
            http_url = url.replace("https://", "http://", 1)
            resp = session.get(http_url, timeout=timeout, allow_redirects=True, **kwargs)
            return resp, None
        except Exception as e:
            return None, str(e)
    except Exception as e:
        return None, str(e)


def safe_head(session: requests.Session, url: str, timeout: int = 10):
    """HEAD request; return (response | None, error_str | None)."""
    try:
        resp = session.head(url, timeout=timeout, allow_redirects=True)
        return resp, None
    except Exception as e:
        return None, str(e)
