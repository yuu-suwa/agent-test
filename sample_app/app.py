from flask import Flask, request, jsonify
from werkzeug.exceptions import BadRequest, UnsupportedMediaType
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
    # 1) Content-Typeチェック（JSON 以外）
    if not request.is_json:
        return jsonify({
            "message": "Invalid request format. JSON required."
        }), 400

    # 2) JSON パース（ここで起きうる例外を個別に捕捉）
    try:
        data = request.get_json()  # invalid JSON -> BadRequest 等
    except BadRequest as e:
        # JSON自体が壊れている/パースできない
        logging.info("Invalid JSON payload on /login: %s", e)
        return jsonify({
            "message": "Invalid JSON."
        }), 400
    except UnsupportedMediaType as e:
        # まれに Content-Type 周りで例外になるケースの保険
        logging.info("Unsupported media type on /login: %s", e)
        return jsonify({
            "message": "Invalid request format. JSON required."
        }), 400
    except Exception:
        # get_json 周りで想定外が起きた場合
        logging.exception("Unexpected error while parsing JSON on /login")
        return jsonify({
            "message": "Internal server error"
        }), 500

    # 3) JSON構造チェック
    if not isinstance(data, dict):
        return jsonify({
            "message": "Invalid JSON structure."
        }), 400

    # 4) パラメータ取り出し
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

    # 5) 認証（ここは予期せぬ例外が起こり得るのでフォールバックを用意）
    try:
        if user_check(username, password):
            return jsonify({
                "message": "login success"
            }), 200
        else:
            # 認証失敗は詳細を出さない
            return jsonify({
                "message": "Authentication failed"
            }), 401
    except Exception:
        logging.exception("Unexpected error during user_check on /login")
        return jsonify({
            "message": "Internal server error"
        }), 500

ALLOWED_USER_TYPES = {"VIP", "NORMAL"}

def parse_price(value):
    """
    priceの入力値(文字列)を安全に数値(Decimal)として解釈する。
    """
    if isinstance(value, str):
        v = value.strip()
        if v == "":
            raise ValueError("empty string")
        return Decimal(v)
    raise TypeError("unsupported type")

@app.route("/price", methods=["POST"])
def price():
    # 1) Content-Typeチェック（JSON以外は拒否）
    if not request.is_json:
        return jsonify({"message": "Invalid request format. JSON required."}), 400

    # 2) JSONパース（起きうる例外を個別に捕捉）
    try:
        data = request.get_json()
    except BadRequest as e:
        logging.info("Invalid JSON payload on /price: %s", e)
        return jsonify({"message": "Invalid JSON."}), 400
    except UnsupportedMediaType as e:
        logging.info("Unsupported media type on /price: %s", e)
        return jsonify({"message": "Invalid request format. JSON required."}), 400
    except Exception:
        logging.exception("Unexpected error while parsing JSON on /price")
        return jsonify({"message": "Internal server error"}), 500

    # 3) JSON構造チェック
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
    try:
        price_value = price_value.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    except (InvalidOperation, ValueError) as e:
        # quantize できないような異常値が来た場合の保険
        logging.info("Invalid price quantize on /price: %s", e)
        return jsonify({"message": "Invalid request parameters. price must be a valid number."}), 400

    # 割引計算（ここは予期せぬ例外が起こり得るのでフォールバックを用意）
    try:
        final_price = calculate_discount(price_value, user_type)
    except Exception:
        logging.exception("Unexpected error during calculate_discount on /price")
        return jsonify({"message": "Internal server error"}), 500

    # final_price をJSON化（Decimalの場合は文字列 or float にする）
    if isinstance(final_price, Decimal):
        final_price_out = str(final_price)
    else:
        final_price_out = final_price

    return jsonify({"final_price": final_price_out}), 200

if __name__ == "__main__":
    app.run(debug=False)