import get_all_user_txs
import json
import statistics as stats

# 'first_sent_block','fees_max','first_block_appeared_in','fees_median','fees_mean','last_block_appeared_in','blocks_btwn_txs_max','blocks_btwn_output_txs_max','blocks_btwn_output_txs_mean'
def get_wallet_feat(walletid):
    get_all_user_txs.get_all_transaction(walletid)

    with open("./wallets/"+walletid.strip()+".json","r") as walletfile:
        features = []
        filedata = json.load(walletfile)
        print(filedata["address"])
        n = len(filedata["txs"])
        no_addr = 0
        fee = list()

        isinput = []
        isoutput = []
        alltxs = []
        if n!=0:
            for tx in filedata["txs"]:
                alltxs.append(tx["block_height"])
                fee.append(tx["fees"])
                if walletid in tx['inputs']['addresses']:
                    isinput.append(tx['block_height'])
                if walletid in tx['outputs']['addresses']:
                    isoutput.append(tx['block_height'])
            alltxs.sort()
            isoutput.sort()
            blocks_btwn_txs_max = 0
            for i in range(len(alltxs)-1):
                for j in range(1,len(alltxs)):
                    diff = alltxs[j] - alltxs[i]
                    if diff > blocks_btwn_txs_max:
                        blocks_btwn_txs_max = diff
            blocks_btn_out = []
            blocks_btwn_output_txs_max = 0
            for i in range(len(isoutput)-1):
                for j in range(1,len(isoutput)):
                    diff = isoutput[j] - isoutput[i]
                    blocks_btn_out.append(diff)
                    if diff > blocks_btwn_output_txs_max:
                        blocks_btwn_output_txs_max = diff
            
            features.append(min(isinput))
            features.append(max(fee))
            features.append(min(isoutput))
            features.append(stats.median(fee))
            features.append(stats.mean(fee))
            features.append(max(isoutput))
            features.append(blocks_btwn_txs_max)
            features.append(blocks_btwn_output_txs_max)
            features.append(stats.mean(blocks_btn_out))

            return features








    