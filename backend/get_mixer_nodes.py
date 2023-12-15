import pandas as pd
import requests 

def getMixer(graph):

    print(graph)
    
    nodes = graph['nodes']

    #each transaction node is iterated, and the input wallets of that transaction are taken from the input_addr file

    for node in nodes:
        #open the file and iterate through each tx
        inputs = pd.read_csv("./transaction_folder/"+node['id']+'_input_addr.csv')
        total_wallets = 0
        wallets_with_one_tx = 0
        for i in range(len(inputs.index)):
            #get the wallet address which performed the each tx
            wallet = inputs['addresses'][i]
            #since the csv file stored it as ['wallet_addr'] as a string, gotta trim that
            start_index = wallet.find("[") + 1
            end_index = wallet.find("]") - 1
            result_string = wallet[start_index + 1:end_index]
            wallet_info = requests.get("https://api.blockcypher.com/v1/btc/main/addrs/" + result_string )
            #get the tx no of the wallet
            wallet_info_json = wallet_info.json()
            if(wallet_info_json['n_tx'] == 1):
                wallets_with_one_tx = wallets_with_one_tx + 1
            total_wallets = total_wallets + 1
        #calculate the percentage
        percent_of_wallets_with_one_tx = wallets_with_one_tx / total_wallets
        #append the property to the node, which will be useful to render it as a diff color in the frontend
        if(percent_of_wallets_with_one_tx >= 0.7):
            node['mixer'] = True
        else:
            node['mixer'] = False

    graph['nodes'] = nodes
    return graph