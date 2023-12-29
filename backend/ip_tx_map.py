import json

with open("./packet.json","r") as packetsfile:
    packetdata = json.load(packetsfile)
    ipdata = []
    '''_source, layers, ip, ip.src
                        bitcoin'''
    for data in packetdata:
        ip = dict()
        layers = data["_source"]["layers"]
        ip["src_ip"] = layers["ip"]["ip.src"]
        txs = []
        for k in layers:
            if k=="bitcoin" and layers[k]["bitcoin.command"]=="tx":
                txs.append(layers[k])
        ip["txs"] = txs
        if len(txs)!=0:
            ipdata.append(ip)

with open("./checkingjsondata.json", "w") as f:
    json.dump(packetdata, f)

with open("./ipmapping.json", "w") as ipfile:
    json.dump(ipdata, ipfile)