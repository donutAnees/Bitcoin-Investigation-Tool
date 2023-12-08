import requests

def get_all_transaction(user_hash):

    user_info_response = requests.get("https://api.blockcypher.com/v1/btc/main/addrs/" + user_hash + "?token=cd380b7fda6a44909bff4645ec8b0448")

    user_info_json = user_info_response.json()

    user_txs = user_info_json.get("txrefs",[])

    with open("./wallets/" + user_hash , "a+") as file:
         for tx in user_txs:
            file.write(str(tx)+'\n')
    file.close()

if __name__ == "__main__":
    with open("./illegal wallets.txt") as file:
        count = 0
        for wallet_id in file:
           get_all_transaction(wallet_id.strip())
    file.close() 