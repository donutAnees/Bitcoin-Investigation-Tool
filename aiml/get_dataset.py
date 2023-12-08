import pandas as pd
import json
import datetime as dt

def create_dataset(walletid, data_list, flag):
    with open("./wallets/"+walletid+".json","r") as walletfile:
        filedata = json.load(walletfile)
        print(filedata["address"])
        n = len(filedata["txs"])
        no_addr = 0
        pref = list()
        lock_time = list()
        fee = list()
        vin_sz = 0
        vout_sz = 0
        count_rbf = 0
        timestamps = list()
        
        if n!=0:
            for tx in filedata["txs"]:
                no_addr += len(tx["addresses"])
                pref.append(tx["preference"])
                if("lock_time" in tx):
                    lock_time.append(tx["lock_time"])
                else:
                    lock_time.append(0)
                fee.append(tx["fees"])
                timestamps.append(dt.datetime.fromisoformat(tx["confirmed"]).timestamp())
                vin_sz += tx["vin_sz"]
                vout_sz += tx["vout_sz"]
                if ("opt_in_rbf" in tx):
                    count_rbf+=1
            
                avg_no_addr = no_addr//n
                avg_vin_sz = vin_sz//n
                avg_vout_sz = vout_sz//n
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

                min_timestamp = min(timestamps)
                timediff = 0
                for ts in timestamps:
                    timediff += ts - min_timestamp
                timestamps_avg = timediff//n
                
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
            data["avg_no_addr"] = avg_no_addr
            data["common_preference"] = com_pref
            data["max_fees"] = max(fee)
            data["max_lock_time"] = max(lock_time)
            data["avg_vin_sz"] = avg_vin_sz
            data["avg_vout_sz"] = avg_vout_sz
            data["rbf_count"] = count_rbf
            data["avg_timestmp_interval"] = timestamps_avg
            data["status"] = status

            data_list.append(data)

if __name__ == "__main__":
    data_list = list()
    
    with open("./illegal_wallets.txt", "r") as illegalfile:
        for walletid in illegalfile:
            create_dataset(walletid.strip(), data_list, 1)
    
    # with open("./wallets.txt", "r") as unknownfile:
    #     for walletid in unknownfile:
    #         create_dataset(walletid, data_list, 0)
    
    df = pd.DataFrame(data_list)
    df.to_csv("./walletsdataset.csv", index = False)