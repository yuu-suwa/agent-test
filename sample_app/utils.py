def calculate_discount(price, user_type):
    if user_type == "VIP":
        return price * Decimal("0.7")
    elif user_type == "NORMAL":
        return price * Decimal("0.9")
    else:
        return price