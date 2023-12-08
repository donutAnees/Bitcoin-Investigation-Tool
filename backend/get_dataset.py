import pandas as pd
import json

def create_dataset(walletid, data_list, flag):
    with open("./wallets/"+walletid+".json","r") as walletfile:
        filedata = json.load(walletfile)

        n = len(tx)
        no_addr = 0
        pref = list()
        lock_time = list()
        fee = list()
        vin_sz = 0
        vout_sz = 0
        count_rbf = 0
        
        if n==0:
            com_pref = None
            fee.append(0)
            lock_time.append(0)

        else:
            for tx in filedata["txs"]:
                no_addr += len(tx["addresses"])
                pref.append(tx["preference"])
                lock_time.append(tx["lock_time"])
                fee.append(tx["fees"])
                vin_sz += tx["vin_sz"]
                vout_sz += tx["vout_sz"]
                if tx["opt_in_rbf"]:
                    count_rbf+=1
            
            low = pref.count("low")
            med = pref.count("medium")
            high = pref.count("high")
            max_pref = max(low,med,high)
            if max_pref == low:
                com_pref = "low"
            elif max_pref == med:
                com_pref = "medium"
            else:
                com_pref = "high"

        if flag == 1:
            status = "illegal"
        else:
            status = "unknown"

        data = dict()
        data["address"] = filedata["address"]
        data["total_received"] = filedata["total_received"]
        data["total_sent"] = filedata["total_sent"]
        data["balance"] = filedata["balance"]
        data["n_tx"] = filedata["n_tx"]
        data["avg_no_addr"] = no_addr//n
        data["common_preference"] = com_pref
        data["max_fees"] = max(fee)
        data["max_lock_time"] = max(lock_time)
        data["avg_vin_sz"] = vin_sz//n
        data["avg_vout_sz"] = vout_sz//n
        data["rbf_count"] = count_rbf
        data["avg_timestmp_interval"]
        data["status"] = status
    
    data_list.append(data)
    return data_list

if __name__ == "__main__":
    data_list = list()
    with open("./illegalwallets.txt", "r") as illegalfile:
        for walletid in illegalfile:
            data_list = create_dataset(walletid, data_list, 1)

    df = pd.DataFrame(data_list)
    df.to_csv("./walletsdataset.csv", index = False)