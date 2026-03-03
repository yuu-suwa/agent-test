def login_user(username, password):
    if user_check( username, password):
        return True
    return False

def user_check(username, password):
    # 別途APIでチェックする想定
    # 入力されたusername、passwordをusername#passwordの文字列に変換してハッシュ値を送信する
    return True