def user_check(username, password):
    # 開発中のため仮実装
    # 本番では別途APIでチェックする想定
    # 入力されたusername、passwordをusername#passwordの文字列に変換してハッシュ値を送信してチェック結果を参照する
    return username == 'admin' and password == 'password'