import requests

tx_file = open('user_transaction_ids','r')
tx_list = tx_file.read().splitlines()

for tx_id in tx_list:
    response = requests.get("https://blockchain.info/rawtx/"+tx_id)
    response_json = response.json()
    no_in = response_json["vin_sz"]
    no_out = response_json["vout_sz"]

    if no_in !=0:
        inp = []
        for i in range(no_in):
            inp.append(response_json["inputs"][i]["prev_out"]["addr"])
    else:
        inp = "NULL"

    if no_out !=0:
        out = []
        for i in range(no_out):
            out.append(response_json["out"][i]["addr"])
    else:
        out = "NULL"




        
    
