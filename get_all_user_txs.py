import requests

def get_all_transaction(user_hash):

    user_info_response = requests.get("https://blockchain.info/rawaddr/" + user_addr)

    user_info_json = user_info_response.json()

    user_txs = user_info_json.get("txs",[])

    with open(user_hash , "a+") as file:
         for tx in user_txs:
            file.write(tx)
    file.close()