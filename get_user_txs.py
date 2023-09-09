import requests

transaction_id = input()

response = requests.get("https://blockchain.info/rawtx/" + transaction_id)

response_json = response.json()

no_of_inputs = response_json["vin_sz"]
no_of_outputs = response_json["vout_sz"]

with open("./user_transaction_ids" , "w+") as file:
    file.write(str(no_of_inputs) + " " + str(no_of_outputs) + "\n")

file.close()

for i in range (no_of_inputs):

    in_field = response_json.get("inputs",[])

    cur_input = in_field[i]

    prev_output = cur_input.get("prev_out", {})

    user_addr = prev_output.get("addr")

    user_info_response = requests.get("https://blockchain.info/rawaddr/" + user_addr)

    user_info_json = user_info_response.json()

    user_txs = user_info_json.get("txs",[])

    with open("./user_transaction_ids" , "a+") as file:
        for tx in user_txs:
            tx_hash = tx.get("hash")
            file.write(tx_hash+'\n')
        file.write("end of input\n")
    file.close()
