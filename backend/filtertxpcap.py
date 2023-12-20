import json
import csv

with open("./pcapdeeps.json", "r") as pcapfile:
    pcapdata = json.load(pcapfile)
    filtereddata = set()
    headers = [
        "ip.dst",
        "ip.src",
        "tcp.srcport",
        "tcp.dstport",
        "frame.time",
        "frame.time_epoch",
        "tcp.payload",
        "bitcoin.command",
    ]

    for data in pcapdata:
        if data.get("_source", {}).get("layers", {}).get("bitcoin.command") is not None:
            layers = data["_source"]["layers"]
            if layers["bitcoin.command"][0] == "tx":
                # Use the combination of relevant fields as a unique identifier for the transaction
                transaction_key = (
                    layers["ip.dst"][0],
                    layers["ip.src"][0],
                    layers["tcp.srcport"][0],
                    layers["tcp.dstport"][0],
                    layers["frame.time"][0],
                    layers["frame.time_epoch"][0],
                    layers["tcp.payload"][0],
                    layers["bitcoin.command"][0],
                )
                filtereddata.add(transaction_key)

# Convert set of tuples to a list
filtereddata_list = [list(item) for item in filtereddata]

with open("./filteredpcap.csv", "w") as filterfile:
    csvwriter = csv.writer(filterfile)
    csvwriter.writerow(headers)
    csvwriter.writerows(filtereddata_list)
