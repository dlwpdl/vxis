"""Explicit cloud-impact probes used by gated post-exploitation steps."""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import re
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request, urlopen


def _aws_signature_key(secret_key: str, date_stamp: str, region: str, service: str) -> bytes:
    k_date = hmac.new(("AWS4" + secret_key).encode(), date_stamp.encode(), hashlib.sha256).digest()
    k_region = hmac.new(k_date, region.encode(), hashlib.sha256).digest()
    k_service = hmac.new(k_region, service.encode(), hashlib.sha256).digest()
    return hmac.new(k_service, b"aws4_request", hashlib.sha256).digest()


def _aws_signed_request(
    *,
    method: str,
    url: str,
    service: str,
    region: str,
    body: str,
    credentials: dict[str, str],
    timeout: float = 5.0,
) -> dict[str, Any]:
    parsed = urlparse(url)
    now = datetime.now(timezone.utc)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    canonical_uri = parsed.path or "/"
    canonical_query = parsed.query
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    headers = {
        "host": parsed.netloc,
        "x-amz-date": amz_date,
        "x-amz-content-sha256": payload_hash,
    }
    if credentials.get("session_token"):
        headers["x-amz-security-token"] = credentials["session_token"]
    if method.upper() == "POST":
        headers["content-type"] = "application/x-www-form-urlencoded; charset=utf-8"
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{key}:{headers[key]}\n" for key in sorted(headers))
    canonical_request = "\n".join(
        [
            method.upper(),
            canonical_uri,
            canonical_query,
            canonical_headers,
            signed_headers,
            payload_hash,
        ]
    )
    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            algorithm,
            amz_date,
            credential_scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    signing_key = _aws_signature_key(
        credentials["secret_access_key"], date_stamp, region, service
    )
    signature = hmac.new(signing_key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    headers["Authorization"] = (
        f"{algorithm} Credential={credentials['access_key_id']}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    request = Request(url, data=body.encode() if body else None, headers=headers, method=method)
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - explicit gated cloud proof
            text = response.read(20000).decode("utf-8", errors="replace")
            return {"ok": 200 <= response.status < 300, "status": response.status, "body": text}
    except Exception as exc:
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _xml_first(tag: str, text: str) -> str:
    match = re.search(rf"<{tag}>([^<]+)</{tag}>", text or "")
    return match.group(1) if match else ""


def _xml_all(tag: str, text: str) -> list[str]:
    return re.findall(rf"<{tag}>([^<]+)</{tag}>", text or "")


def probe_aws_identity_and_storage(credentials: dict[str, str]) -> dict[str, Any]:
    """Call low-risk AWS identity/storage metadata APIs with explicit credentials."""
    sts = _aws_signed_request(
        method="POST",
        url="https://sts.amazonaws.com/",
        service="sts",
        region="us-east-1",
        body="Action=GetCallerIdentity&Version=2011-06-15",
        credentials=credentials,
    )
    sts_summary: dict[str, Any] = {
        "ok": bool(sts.get("ok")),
        "status": sts.get("status"),
        "error": sts.get("error", ""),
    }
    body = str(sts.get("body") or "")
    for key in ("Arn", "Account", "UserId"):
        value = _xml_first(key, body)
        if value:
            sts_summary[key.lower()] = value

    s3 = _aws_signed_request(
        method="GET",
        url="https://s3.amazonaws.com/",
        service="s3",
        region="us-east-1",
        body="",
        credentials=credentials,
    )
    s3_body = str(s3.get("body") or "")
    bucket_names = _xml_all("Name", s3_body)[:10] if s3.get("ok") else []
    return {
        "sts": sts_summary,
        "s3": {
            "ok": bool(s3.get("ok")),
            "status": s3.get("status"),
            "error": s3.get("error", ""),
            "bucket_count_observed": len(bucket_names),
            "bucket_names_preview": bucket_names,
        },
    }
