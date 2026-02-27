# ダミーユーザーDB（ハードコード）
USERS = {
    "admin": "password123",
    "user": "1234"
}

def login_user(username, password):
    if username in USERS:
        if USERS[username] == password:
            return True
    return False