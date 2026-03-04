import os
import base64
import hashlib
import hmac
import json
import urllib.request
import urllib.error
from typing import Optional

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

    # Fallback
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
            # JSONでなければ素の文字列として扱う
            pass
    return raw

def get_dev_auth_hash() -> Optional[str]:
    """
    DEV: 固定AUTH_HASHをSecret Managerから取得。
    - DEV_SECRET_PROVIDER: "aws" | "gcp"
    - DEV_AUTH_HASH_SECRET_ID (aws) / DEV_AUTH_HASH_SECRET_NAME (gcp)
    """
    provider = os.getenv("DEV_SECRET_PROVIDER") or "aws"
    raw = _get_secret_raw(provider, "DEV_AUTH_HASH_SECRET_ID", "DEV_AUTH_HASH_SECRET_NAME")
    return _extract_value(raw, "AUTH_HASH")

def get_prod_pepper() -> Optional[bytes]:
    """
    PROD: pepper（秘密鍵）をSecret Managerから取得。
    - PROD_SECRET_PROVIDER: "aws" | "gcp"
    - PROD_PEPPER_SECRET_ID (aws) / PROD_PEPPER_SECRET_NAME (gcp)
    secret valueは以下どれでもOK:
      - 生文字列（十分長いランダム推奨）
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

    # 生文字列はUTF-8 bytes化（本当はランダムbytesをbase64で管理するのが推奨）
    return v.encode("utf-8")


# ==========================================
# deterministic token derivation for API
# ==========================================
# 固定salt（pepper必須）。環境差分が出ないよう固定値。
def derive_auth_token(username: str, password: str, pepper: bytes) -> str:
    """
    username+passwordから決定的に token を導出（passwordは直接送らない）。
    token は base64url 文字列で返す。

    設計:
      1) material = f"{username}#{password}"
      2) prekey = HMAC-SHA256(pepper, material)  -> 32 bytes
      3) token_bytes = scrypt(prekey, fixed_salt, high_cost) -> 32 bytes
    """
    if not pepper:
        raise RuntimeError("pepper is empty")

    material = f"{username}#{password}".encode("utf-8")
    prekey = hmac.new(pepper, material, hashlib.sha256).digest()
    fixed_salt = (os.getenv("AUTH_TOKEN_SALT") or "auth-token-salt-v1").encode("utf-8")

    # コストは本番要件に応じて調整（API側も同じパラメータで導出すること）
    n = int(os.getenv("AUTH_TOKEN_SCRYPT_N") or str(2**14))
    r = int(os.getenv("AUTH_TOKEN_SCRYPT_R") or "8")
    p = int(os.getenv("AUTH_TOKEN_SCRYPT_P") or "1")
    dklen = int(os.getenv("AUTH_TOKEN_SCRYPT_DKLEN") or "32")

    token_bytes = hashlib.scrypt(
        prekey,
        salt=fixed_salt,
        n=n,
        r=r,
        p=p,
        dklen=dklen,
    )
    return base64.urlsafe_b64encode(token_bytes).decode("ascii").rstrip("=")

def call_auth_api_with_token(username: str, token: str) -> bool:
    """
    認証APIに {username, token} を送信し
    {"ok": true/false} を返す仕様に対応。
    失敗時は fail-closed (False)。
    """
    url = os.getenv("AUTH_API_URL")
    if not url:
        raise RuntimeError("AUTH_API_URL is not set")

    api_key = os.getenv("AUTH_API_KEY")
    timeout = float(os.getenv("AUTH_API_TIMEOUT_SEC", "3"))

    payload = json.dumps({
        "username": username,
        "token": token
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, method="POST")
    req.add_header("Content-Type", "application/json")

    if api_key:
        req.add_header("Authorization", f"Bearer {api_key}")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # ステータスコードチェック
            if resp.status != 200:
                return False
            body = resp.read().decode("utf-8")
            if not body:
                return False

            data = json.loads(body)
            # 仕様: {"ok": true} / {"ok": false}
            ok = data.get("ok")
            if isinstance(ok, bool):
                return ok
            return False

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

    token = derive_auth_token(username, password, pepper)

    # --- 本番 ---
    if mode == "prod":
        return call_auth_api_with_token(username, token)

    # --- 開発 ---
    stored_hash = get_dev_auth_hash()
    if not stored_hash:
        return False

    return hmac.compare_digest(token, stored_hash)