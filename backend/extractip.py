#updated code which does the entire wallet extraction process

import os
import json
import json
import csv
from getwalletid import get_address

print("enter input and output filenames:")
input, output= input().split()

output_filename=output+'.json'
cmd ='tshark -r {}.pcap --no-duplicate-keys -T json > {}.json'
final_cmd = cmd.format(input, output)
os.system(final_cmd)

with open(output+".json","r") as packetsfile:
    packetdata = json.load(packetsfile)
    ipdata = []
    '''_source, layers, ip, ip.src
                        bitcoin'''
    for data in packetdata:
        ip = dict()
        layers = data["_source"]["layers"]
        if layers.get("ip") is not None:
            ip["time"] = layers["frame"]["frame.time"]
            ip["src_ip"] = layers["ip"]["ip.src"]
        else:
            continue

        txs = []

        if layers.get("bitcoin") is not None:
            bitcoin = layers["bitcoin"]
        else:
            continue

        if type(bitcoin) == list:
            for i in bitcoin:
                if(i["bitcoin.command"] == "tx"):
                    txs.append(i["bitcoin.tx"])  
        else:
            if(bitcoin["bitcoin.command"] == "tx"):
                txs.append(bitcoin["bitcoin.tx"])
            else:
                continue

        ip["txs"] = txs
        if len(txs)!=0:
            ipdata.append(ip)

with open("./extracted.json", "w") as ipfile:
    json.dump(ipdata, ipfile)
ipfile.close()

file_path = "./extracted.json"
output_file_path = "./output.csv"

with open(file_path, "r") as file:
    filedata = json.load(file)

with open(output_file_path, mode='w', newline='') as output_file:
    csv_writer = csv.writer(output_file)
    csv_writer.writerow(["Source IP", "Time", "Input Wallets", "Output Wallets"])

    for data in filedata:
        input_wallets = []
        output_wallets = []
        for tx in data["txs"]:
            if tx.get("bitcoin.tx.in") is not None:
                if isinstance(tx["bitcoin.tx.in"], list):
                    for txin in tx["bitcoin.tx.in"]:
                        if "bitcoin.tx.in.sig_script" in txin:
                            input_wallets.append(get_address(txin["bitcoin.tx.in.sig_script"], "00", 1))
                else:
                    if "bitcoin.tx.in.sig_script" in tx["bitcoin.tx.in"]:
                        input_wallets.append(get_address(tx["bitcoin.tx.in"]["bitcoin.tx.in.sig_script"], "00",1))
            if tx.get("bitcoin.tx.out") is not None:
                if isinstance(tx["bitcoin.tx.out"], list):
                    for txout in tx["bitcoin.tx.out"]:
                        if "bitcoin.tx.out.script" in txout:
                            output_wallets.append(get_address(txout["bitcoin.tx.out.script"], "00",0))
                else:
                    if "bitcoin.tx.out.script" in tx["bitcoin.tx.out"]:
                        output_wallets.append(get_address(tx["bitcoin.tx.out"]["bitcoin.tx.out.script"], "00",0))

        csv_writer.writerow([data["src_ip"], data["time"], ', '.join(input_wallets) if input_wallets else "NA",
                             ', '.join(output_wallets) if output_wallets else "NA"])
