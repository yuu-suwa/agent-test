from flask import Flask, request, jsonify
from auth import user_check
from utils import calculate_discount

app = Flask(__name__)

@app.route("/")
def home():
    return "hello world"

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({"message": "Invalid Request. Request body must be valid JSON."}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"message": "Invalid Request. Both UserName and Password are required"}), 400

    if user_check(username, password):
        return jsonify({"message": "login success"})
    else:
        return jsonify({"message": "login failed"}), 401


@app.route("/price", methods=["POST"])
def price():
    data = request.get_json(force=True, silent=True)
    if data is None:
        return jsonify({"message": "Invalid Request. Request body must be valid JSON."}), 400

    price = data.get("price")
    user_type = data.get("user_type")

    if not price or not user_type:
        return jsonify({"message": "Invalid Request. Both Price and UserType are required."}), 400
    if not isinstance(price, (int, float)) or price < 0:
        return jsonify({"message": "Invalid Request. Price must be positive value."}), 400
    if user_type not in ("VIP", "NORMAL"):
        return jsonify({"message": "Invalid Request. Unexpected value passed for UserType."}), 400

    final_price = calculate_discount(price, user_type)

    return jsonify({"final_price": final_price})


if __name__ == "__main__":
    app.run(debug=False)