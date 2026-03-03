from flask import Flask, request, jsonify
from auth import user_check
from utils import calculate_discount
from decimal import Decimal, InvalidOperation, ROUND_HALF_UP
import logging

app = Flask(__name__)

@app.route("/")
def home():
    return "hello world"

@app.route("/login", methods=["POST"])
def login():
    try:
        # Content-Typeチェック
        if not request.is_json:
            return jsonify({
                "message": "Invalid request format. JSON required."
            }), 400

        data = request.get_json()

        if not isinstance(data, dict):
            return jsonify({
                "message": "Invalid JSON structure."
            }), 400

        username = data.get("username")
        password = data.get("password")

        # 型チェック + 空文字チェック
        if not isinstance(username, str) or not isinstance(password, str):
            return jsonify({
                "message": "Invalid request parameters."
            }), 400

        username = username.strip()

        if username == "" or password == "":
            return jsonify({
                "message": "Invalid request parameters."
            }), 400

        # 認証
        if user_check(username, password):
            return jsonify({
                "message": "login success"
            }), 200
        else:
            # 認証失敗は詳細を出さない
            return jsonify({
                "message": "Authentication failed"
            }), 401

    except Exception as e:
        logging.exception("Unexpected error during login")
        return jsonify({
            "message": "Internal server error"
        }), 500

ALLOWED_USER_TYPES = {"VIP", "NORMAL"}

def parse_price(value):
    """
    price を安全に数値として解釈する。
    - int/float/Decimal はOK
    - "1000" や "1000.50" のような文字列も許可したい場合はここで対応
    """
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, str):
        v = value.strip()
        if v == "":
            raise ValueError("empty string")
        return Decimal(v)
    raise TypeError("unsupported type")

@app.route("/price", methods=["POST"])
def price():
    try:
        # Content-Typeチェック（JSON以外は拒否）
        if not request.is_json:
            return jsonify({"message": "Invalid request format. JSON required."}), 400

        data = request.get_json()
        if not isinstance(data, dict):
            return jsonify({"message": "Invalid JSON structure."}), 400

        raw_price = data.get("price")
        user_type = data.get("user_type")

        # 必須チェック（Noneを明確に弾く。0は有効値なので not price は使わない）
        if raw_price is None or user_type is None:
            return jsonify({"message": "Invalid request parameters. price and user_type are required."}), 400

        # user_type チェック
        if not isinstance(user_type, str):
            return jsonify({"message": "Invalid request parameters."}), 400

        user_type = user_type.strip().upper()
        if user_type not in ALLOWED_USER_TYPES:
            return jsonify({"message": "Invalid request parameters."}), 400

        # price チェック
        try:
            price_value = parse_price(raw_price)
        except (InvalidOperation, ValueError, TypeError):
            return jsonify({"message": "Invalid request parameters. price must be a number."}), 400

        if price_value < 0:
            return jsonify({"message": "Invalid request parameters. price must be >= 0."}), 400

        # 例: 小数2桁に丸め
        price_value = price_value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)

        # 割引計算（calculate_discount 側の実装次第で float 返るかもなので Decimal で統一推奨）
        final_price = calculate_discount(price_value, user_type)

        # final_price をJSON化（Decimalの場合は文字列 or float にする）
        if isinstance(final_price, Decimal):
            final_price_out = str(final_price)
        else:
            final_price_out = final_price

        return jsonify({"final_price": final_price_out}), 200

    except Exception:
        logging.exception("Unexpected error during /price")
        return jsonify({"message": "Internal server error"}), 500

if __name__ == "__main__":
    app.run(debug=False)