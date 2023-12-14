import pandas as pd
import requests 

def getMixer(graph):
    nodes = graph['nodes']

    for node in nodes:
        inputs = pd.read_csv("./transaction_folder/"+node['id']+'_input_addr.csv')
        total_wallets = 0
        wallets_with_one_tx = 0
        for i in range(len(inputs.index)):
            wallet = inputs['addresses'][i]
            start_index = wallet.find("[") + 1
            end_index = wallet.find("]") - 1
            result_string = wallet[start_index + 1:end_index]
            wallet_info = requests.get("https://api.blockcypher.com/v1/btc/main/addrs/" + result_string )
            wallet_info_json = wallet_info.json()
            if(wallet_info_json['n_tx'] == 1):
                wallets_with_one_tx = wallets_with_one_tx + 1
            total_wallets = total_wallets + 1
    
        percent_of_wallets_with_one_tx = wallets_with_one_tx / total_wallets

        if(percent_of_wallets_with_one_tx >= 0.7):
            node['mixer'] = True
        else:
            node['mixer'] = False

    graph['nodes'] = nodes
    return graph