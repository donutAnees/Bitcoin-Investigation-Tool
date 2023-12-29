import json

with open("./packet.json","r") as packetsfile:
    packetdata = json.load(packetsfile)
    ipdata = []
    '''_source, layers, ip, ip.src
                        bitcoin'''
    for data in packetdata:
        ip = dict()
        layers = data["_source"]["layers"]
        if layers.get("ip") is not None:
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

with open("./ipmapping.json", "w") as ipfile:
    json.dump(ipdata, ipfile)
ipfile.close()