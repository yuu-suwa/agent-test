from flask import Flask, request, jsonify
from auth import login_user
from utils import calculate_discount
import os

DEBUG_ON = os.environ["DEBUG_ON"]

app = Flask(__name__)

@app.route("/")
def home():
    return "hello world"

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True)
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Invalid Request"}), 400

    # パスワード平文比較（NG）
    if login_user(username, password):
        return jsonify({"message": "login success"})
    else:
        return jsonify({"message": "login failed"}), 401


@app.route("/price", methods=["POST"])
def price():
    data = request.get_json(force=True, silent=True)
    price = data.get("price")
    user_type = data.get("user_type")

    if not price or not isinstance(price, (int, float)) or not user_type:
        return jsonify({"message": "Invalid Request"}), 400

    final_price = calculate_discount(price, user_type)

    return jsonify({"final_price": final_price})


if __name__ == "__main__":
    app.run(debug=DEBUG_ON)