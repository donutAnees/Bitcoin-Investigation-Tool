import socket
import os
import subprocess
import json
import datetime
import csv
#import psycopg2
from getwalletid import get_address
from getTransactionId import decodeJSONBitcoinPayload
'''
    This is the main file which accepts  pcap file. From the pcap's json file, this program extracts the required fields needed for de-anonymization 
    and output's it to extracted{$}.json. This extracted json is then parsed and the necessary calculation is done on the fields. The results are 
    then stored in a database or returned as csv.
''' 

#Checks the lenght of the script, if the script lenght is 0, then that tx is dropped as a transaction should not have a script lenght of size 0 
def isValidScript(script):
    return len(script) > 0

# # postgreSQL is used for the DB
# hostname = 'localhost'  
# database = 'postgres'  # Replace with your database name
# username = 'postgres'  # Replace with your username
# password = 'postgres'  # Replace with your password
# port = 5432  # Default PostgreSQL port
#conn = None

hostname = socket.gethostname()
IP = socket.gethostbyname(hostname)

# try:
#     conn = psycopg2.connect(
#         host=hostname,
#         database=database,
#         user=username,
#         password=password,
#         port=port
#     )
#     cur = conn.cursor()

# except (Exception, psycopg2.Error) as error:
#     print("Error connecting to PostgreSQL database:", error)
#     quit()

input_directory = "../capture"

output_file_path = "./" + input_directory + "/output.csv"
input_file_path = "./" + input_directory + "/input.csv"

with open(output_file_path, mode='w', newline='') as output_file:
            csv_writer = csv.writer(output_file)
            csv_writer.writerow(["Source IP", "Time", "Output Wallets" , "Amount","TxID"])

with open(input_file_path, mode='w', newline='') as input_file:
            csv_writer = csv.writer(input_file)
            csv_writer.writerow(["Source IP", "Time", "Input Wallets","TxID"])

packetdata = []

for filename in os.listdir(input_directory):
    if filename.endswith(".pcapng"):
        output_filename = os.path.splitext(filename)[0] + '.json'

        cmd = ['tshark', '-r', os.path.join(input_directory, filename), '--no-duplicate-keys', '-Y' , f'bitcoin.tx && ip.src != {IP}' ,'-T', 'json']
        output = subprocess.check_output(cmd)

        packetdata = json.loads(output)

        ipdata = []
        for data in packetdata:
            ip = dict()
            layers = data["_source"]["layers"]

            # Gets the IP and the timestamp
            if layers.get("ip") is not None:
                ip["time"] = layers["frame"]["frame.time"]
                ip["src_ip"] = layers["ip"]["ip.src"]
            else:
                continue

            txs = []

            # Sees if the packet is a bitcoin packet
            if layers.get("bitcoin") is not None:
                bitcoin = layers["bitcoin"]
            else:
                continue
                
            #if it is a bitcoin packet, next step is to determine what type of a bitcoin packet it is, we are only interested in packets which are for transaction
            try:
                if type(bitcoin) == list:
                    for i in bitcoin:
                        if(i["bitcoin.command"] == "tx"):
                            txs.append(i["bitcoin.tx"])  
                else:
                    if(bitcoin["bitcoin.command"] == "tx"):
                        txs.append(bitcoin["bitcoin.tx"])
                    else:
                        continue
            except:
                continue

            ip["txs"] = txs
            if len(txs)!=0:
                ipdata.append(ip)

        for data in ipdata:
                    input_wallets = []
                    output_wallets = []
                    txID = ""
                    for tx in data["txs"]:
                        try:
                            txID = decodeJSONBitcoinPayload(tx) #The txID is computed from the tx data                   
                            # from the input field, we derive the wallet addresses

                            if tx.get("bitcoin.tx.in") is not None:
                                if isinstance(tx["bitcoin.tx.in"], list):
                                    for txin in tx["bitcoin.tx.in"]: # for each input in the transaction
                                        if "bitcoin.tx.in.sig_script" in txin:
                                            if(isValidScript(txin["bitcoin.tx.in.sig_script"])):
                                                input_wallets.append(get_address(txin["bitcoin.tx.in.sig_script"], 1)) 
                                            else:
                                                input_wallets.append("unknown")
                                else:
                                    if "bitcoin.tx.in.sig_script" in tx["bitcoin.tx.in"]:
                                        if(isValidScript(tx["bitcoin.tx.in"]["bitcoin.tx.in.sig_script"])):
                                            input_wallets.append(get_address(tx["bitcoin.tx.in"]["bitcoin.tx.in.sig_script"],1))
                                        else:
                                            input_wallets.append("unknown")
                            
                            # from the output field, we derive the wallet addresses
                            if tx.get("bitcoin.tx.out") is not None:
                                if isinstance(tx["bitcoin.tx.out"], list):
                                    for txout in tx["bitcoin.tx.out"]:  # for each output in the transaction
                                        if "bitcoin.tx.out.script" in txout:
                                            if(isValidScript(txout["bitcoin.tx.out.script"])):
                                                output_wallets.append([get_address(txout["bitcoin.tx.out.script"],0),int(txout["bitcoin.tx.out.value"])])
                                            else:
                                                continue
                                        else:
                                            if "bitcoin.tx.out.script" in tx["bitcoin.tx.out"]:
                                                if(isValidScript(tx["bitcoin.tx.out"]["bitcoin.tx.out.script"])):
                                                    output_wallets.append([get_address(tx["bitcoin.tx.out"]["bitcoin.tx.out.script"],0),int(tx["bitcoin.tx.out"]["bitcoin.tx.out.value"])])
                                                else:
                                                    continue
                        except:
                            continue

                    # inwalletsql = """
                    #     INSERT INTO transaction_input (TXID, SOURCE_IP, TIMESTAMP, WALLET)
                    #     VALUES (%s, %s, %s,%s)
                    # """
                    # outwalletsql = """
                    #     INSERT INTO transaction_output (TXID, SOURCE_IP, TIMESTAMP, WALLET, AMOUNT)
                    #     VALUES (%s, %s, %s, %s, %s)
                    # """

                    # ipsql = """
                    #     INSERT INTO currentIP (IP)
                    #     VALUES (%s)
                    # """


                    # # the data is written to the database
                    # try:
                    #     timestamp = data["time"]
                    #     timestamp, timezone_str = timestamp.rsplit(' ', 1)
                    #     timestamp = timestamp[:-3]
                    #     date_time_obj = datetime.datetime.strptime(timestamp, "%b %d, %Y %H:%M:%S.%f") 
               
                    #     cur.execute(ipsql,(data["src_ip"],))

                    #     if input_wallets:
                    #         for wallet in input_wallets:
                    #             #print(txID,data["src_ip"],date_time_obj,wallet,location)
                    #             cur.execute(inwalletsql,(txID,data["src_ip"],date_time_obj, wallet))
                    #     if output_wallets:
                    #         for wallet in output_wallets:
                    #             #print(txID,data["src_ip"],date_time_obj, wallet[0],wallet[1]/100000000,location)
                    #             cur.execute(outwalletsql,(txID,data["src_ip"],date_time_obj, wallet[0],wallet[1]/100000000))
                    
                    # except (Exception, psycopg2.Error) as error:
                    #     print("Error writing data to database:", error)
                    #     continue
                    with open(output_file_path, mode='a+', newline='') as output_file:
                        csv_writer = csv.writer(output_file)
                        for wallet in output_wallets:
                            csv_writer.writerow([data["src_ip"], data["time"], wallet[0] , "{:.8f}".format(wallet[1]/100000000),txID])
        
                    with open(input_file_path, mode='a+', newline='') as input_file:
                        csv_writer = csv.writer(input_file)
                        for wallet in input_wallets:
                            csv_writer.writerow([data["src_ip"], data["time"],wallet,txID])   
    # conn.commit()                           
    
        del packetdata
    
# cur.close()
# conn.close()