import requests

transaction_id = input()

response = requests.get("https://blockchain.info/rawtx/" + transaction_id)

response_json = response.json()

in_field = response_json.get("inputs",[])

first_input = in_field[0]

prev_output = first_input.get("prev_out", {})

user_addr = prev_output.get("addr")

user_info_response = requests.get("https://blockchain.info/rawaddr/" + user_addr)

user_info_json = user_info_response.json()

user_txs = user_info_json.get("txs",[])

with open("./user_transaction_ids" , "w+") as file:
    for tx in user_txs:
        tx_hash = tx.get("hash")
        file.write(tx_hash+'\n')

file.close()