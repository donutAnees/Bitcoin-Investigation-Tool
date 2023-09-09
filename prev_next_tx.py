import requests

tx_file = open('','r')
tx_list = []

for tx_id in tx_list:
    response = requests.get("https://blockchain.info/rawtx/"+tx_id)
    response_json = response.json()
    no_in = response_json["vin_sz"]
    no_out = response_json["vout_sz"]
    