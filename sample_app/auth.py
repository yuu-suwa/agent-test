import os
import hashlib
import hmac

def hash_credentials(username: str, password: str) -> str:
    combined = f"{username}#{password}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()

def user_check(username: str, password: str) -> bool:

    input_hash = hash_credentials(username, password)
    # 仮実装 環境変数から固定値取得
    stored_hash = os.getenv("AUTH_HASH")
    return hmac.compare_digest(input_hash, stored_hash)