import json
from parser import get_address

file_path = "./extracted.json"  

with open(file_path, "r") as file:
    filedata = json.load(file)
    
for data in filedata:
   print("Source IP:", data["src_ip"] , end="\t\t")
   input_wallets = []
   output_wallets = []
   for tx in data["txs"]:
      if (tx.get("bitcoin.tx.in") is not None):
         if(type(tx["bitcoin.tx.in"]) == list):
            for txin in tx["bitcoin.tx.in"]:    
               input_wallets.append(txin["bitcoin.tx.in.sig_script"])
         else:
             input_wallets.append(tx["bitcoin.tx.in"]["bitcoin.tx.in.sig_script"])
      if (tx.get("bitcoin.tx.out") is not None):
         if(type(tx["bitcoin.tx.out"]) == list):
            for txout in tx["bitcoin.tx.out"]:
               output_wallets.append(txout["bitcoin.tx.out.script"])
         else:
            if (tx.get("bitcoin.tx.out.script") is not None):
               output_wallets.append(tx["bitcoin.tx.out"]["bitcoin.tx.out.script"])
   if(len(input_wallets) == 0):
      print("NA" , end="\t\t")
   else:
      for in_script in input_wallets:
         address = get_address(in_script , "00")
         print(address , end=" ")

   if(len(output_wallets) == 0):
      print("NA")
   else:
      for out_script in output_wallets:
         address = get_address(out_script , "00")
         print(address , end=" ")
      print("\n")