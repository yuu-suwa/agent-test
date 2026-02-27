from flask import Flask, request, jsonify
from auth import login_user
from utils import calculate_discount

app = Flask(__name__)

@app.route("/")
def home():
    return "hello world"  # ← マジック文字列

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    # パスワード平文比較（NG）
    if login_user(username, password):
        return jsonify({"message": "login success"})
    else:
        return jsonify({"message": "login failed"}), 401


@app.route("/price", methods=["POST"])
def price():
    data = request.json
    price = data.get("price")
    user_type = data.get("user_type")

    # 型チェックなし
    final_price = calculate_discount(price, user_type)

    return jsonify({"final_price": final_price})


if __name__ == "__main__":
    app.run(debug=True)  # ← 本番でdebug=True