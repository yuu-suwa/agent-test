import os
import base64
import hashlib
import hmac
import json
import urllib.parse
import urllib.request
import urllib.error
from typing import Optional, Tuple


# =========================
# Secret retrieval (DEV/PROD)
# =========================
def _get_secret_from_aws_secrets_manager(secret_id: str, region: Optional[str] = None) -> str:
    try:
        import boto3  # type: ignore
    except Exception as e:
        raise RuntimeError("boto3 is required for AWS Secrets Manager") from e

    client = boto3.client("secretsmanager", region_name=region)
    resp = client.get_secret_value(SecretId=secret_id)

    if "SecretString" in resp and resp["SecretString"]:
        return resp["SecretString"]

    b = resp.get("SecretBinary")
    if not b:
        raise RuntimeError("Secret has no SecretString/SecretBinary")
    return base64.b64decode(b).decode("utf-8")


def _get_secret_from_gcp_secret_manager(secret_name: str) -> str:
    try:
        from google.cloud import secretmanager  # type: ignore
    except Exception as e:
        raise RuntimeError("google-cloud-secret-manager is required for GCP Secret Manager") from e

    client = secretmanager.SecretManagerServiceClient()
    resp = client.access_secret_version(name=secret_name)
    return resp.payload.data.decode("utf-8")


def _get_secret_raw(provider: str, secret_id_env: str, secret_name_env: str) -> str:
    provider = (provider or "").strip().lower()
    if provider == "aws":
        secret_id = os.getenv(secret_id_env)
        if not secret_id:
            raise RuntimeError(f"{secret_id_env} is not set")
        region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION")
        return _get_secret_from_aws_secrets_manager(secret_id, region=region)

    if provider == "gcp":
        secret_name = os.getenv(secret_name_env)
        if not secret_name:
            raise RuntimeError(f"{secret_name_env} is not set")
        return _get_secret_from_gcp_secret_manager(secret_name)

    # Fallback（非推奨）
    return os.getenv(secret_id_env) or ""


def _extract_value(raw: str, key: str) -> Optional[str]:
    raw = (raw or "").strip()
    if not raw:
        return None
    if raw.startswith("{"):
        try:
            obj = json.loads(raw)
            v = obj.get(key)
            return v.strip() if isinstance(v, str) and v.strip() else None
        except Exception:
            pass
    return raw


def get_dev_auth_material() -> Tuple[Optional[str], Optional[str]]:
    """
    DEV: 固定の salt と token を Secret Manager から取得。
    Secretは以下どちらでもOK:
      - JSON {"AUTH_SALT":"...","AUTH_TOKEN":"..."}
      - AUTH_TOKENだけ(従来互換) ※ただし salt が無いとこの方式は使えないのでNG扱いにする
    """
    provider = os.getenv("DEV_SECRET_PROVIDER") or "aws"
    raw = _get_secret_raw(provider, "DEV_AUTH_SECRET_ID", "DEV_AUTH_SECRET_NAME")

    salt = _extract_value(raw, "AUTH_SALT")
    token = _extract_value(raw, "AUTH_TOKEN")
    return salt, token


def get_prod_pepper() -> Optional[bytes]:
    """
    PROD: pepper（秘密鍵）をSecret Managerから取得。
    - PROD_SECRET_PROVIDER: "aws" | "gcp"
    - PROD_PEPPER_SECRET_ID (aws) / PROD_PEPPER_SECRET_NAME (gcp)
    secret value:
      - 生文字列（推奨: base64:...）
      - base64:... 形式
      - JSON {"PEPPER":"..."}
    """
    provider = os.getenv("PROD_SECRET_PROVIDER") or "aws"
    raw = _get_secret_raw(provider, "PROD_PEPPER_SECRET_ID", "PROD_PEPPER_SECRET_NAME")
    v = _extract_value(raw, "PEPPER")
    if not v:
        return None

    v = v.strip()
    if v.startswith("base64:"):
        return base64.b64decode(v[len("base64:"):].encode("ascii"))

    return v.encode("utf-8")


# ==========================================
# token derivation (per-user salt)
# ==========================================
def derive_auth_token(username: str, password: str, pepper: bytes, salt_b64: str) -> str:
    """
    username + password + (per-user salt) + pepper から token を導出。
    salt はユーザーごとにユニークなランダム値（base64url文字列）を想定。

    設計:
      1) material = f"{username}#{password}"
      2) prekey = HMAC-SHA256(pepper, material) -> 32 bytes
      3) token_bytes = scrypt(prekey, user_salt, high_cost) -> 32 bytes
    """
    if not pepper:
        raise RuntimeError("pepper is empty")
    if not salt_b64 or not isinstance(salt_b64, str):
        raise RuntimeError("salt is required")

    # base64url decode（padding省略も許容）
    padded = salt_b64 + "=" * (-len(salt_b64) % 4)
    user_salt = base64.urlsafe_b64decode(padded.encode("ascii"))

    material = f"{username}#{password}".encode("utf-8")
    prekey = hmac.new(pepper, material, hashlib.sha256).digest()

    n = int(os.getenv("AUTH_TOKEN_SCRYPT_N") or str(2**14))
    r = int(os.getenv("AUTH_TOKEN_SCRYPT_R") or "8")
    p = int(os.getenv("AUTH_TOKEN_SCRYPT_P") or "1")
    dklen = int(os.getenv("AUTH_TOKEN_SCRYPT_DKLEN") or "32")

    token_bytes = hashlib.scrypt(
        prekey,
        salt=user_salt,  # ★ per-user salt
        n=n,
        r=r,
        p=p,
        dklen=dklen,
    )
    return base64.urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")


# =========================
# PROD: fetch per-user salt
# =========================
def fetch_user_salt(username: str) -> Optional[str]:
    """
    本番: username に紐づく per-user salt を API から取得する（2段階方式）。

    期待レスポンス例:
      {"salt": "<base64url>"}
    """
    base = os.getenv("AUTH_API_URL_SALT")
    if not base:
        raise RuntimeError("AUTH_API_URL_SALT is not set")

    api_key = os.getenv("AUTH_API_KEY")
    timeout = float(os.getenv("AUTH_API_TIMEOUT_SEC", "3"))

    qs = urllib.parse.urlencode({"username": username})
    url = f"{base}?{qs}"

    req = urllib.request.Request(url, method="GET")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return None
            body = resp.read().decode("utf-8")
            if not body:
                return None
            data = json.loads(body)
            salt = data.get("salt")
            return salt if isinstance(salt, str) and salt.strip() else None
    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError
    ):
        return None


def call_auth_api_with_token(username: str, token: str, salt_b64: Optional[str] = None) -> bool:
    """
    認証APIに {username, token[, salt]} を送信し {"ok": true/false} で判断。
    ※ salt はAPI側で監査ログ等に使えるので送っておくと便利（必須でなければOptional）
    """
    url = os.getenv("AUTH_API_URL")
    if not url:
        raise RuntimeError("AUTH_API_URL is not set")

    api_key = os.getenv("AUTH_API_KEY")
    timeout = float(os.getenv("AUTH_API_TIMEOUT_SEC", "3"))

    payload_obj = {"username": username, "token": token}
    if salt_b64:
        payload_obj["salt"] = salt_b64

    payload = json.dumps(payload_obj).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")
    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return False
            body = resp.read().decode("utf-8")
            if not body:
                return False

            data = json.loads(body)
            ok = data.get("ok")
            return bool(ok) if isinstance(ok, bool) else False

    except (
        urllib.error.HTTPError,
        urllib.error.URLError,
        TimeoutError,
        json.JSONDecodeError
    ):
        return False


def user_check(username: str, password: str) -> bool:
    mode = (os.getenv("AUTH_MODE") or "dev").strip().lower()

    pepper = get_prod_pepper()
    if not pepper:
        return False

    # --- 本番: salt取得 → token導出 → verify ---
    if mode == "prod":
        salt_b64 = fetch_user_salt(username)
        if not salt_b64:
            return False
        token = derive_auth_token(username, password, pepper, salt_b64)
        return call_auth_api_with_token(username, token, salt_b64=salt_b64)

    # --- 開発: Secret Managerに保存してある(salt, token)と照合 ---
    salt_b64, stored_token = get_dev_auth_material()
    if not salt_b64 or not stored_token:
        return False

    token = derive_auth_token(username, password, pepper, salt_b64)
    return hmac.compare_digest(token, stored_token)