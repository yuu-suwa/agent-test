def calculate_discount(price, user_type):
    if user_type == "VIP":
        return price * 0.7
    elif user_type == "NORMAL":
        return price * 0.9
    else:
        return price