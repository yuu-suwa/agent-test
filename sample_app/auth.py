import hashlib
import hmac

VALID_HASH = "正しいハッシュ値"

def user_check(username: str, password: str) -> bool:
    combined = f"{username}#{password}"
    input_hash = hashlib.sha256(combined.encode("utf-8")).hexdigest()
    return hmac.compare_digest(input_hash, VALID_HASH)