# Bitcoin-Investigation-Tool

This is a bitcoin investigation tool which provides the following tools 
- Interactive Blockchain Transaction Visualizer 
- Bitcoin PCAP Decoder
- Online Wallet Search

## Project Overview
<img width="1375" alt="Screenshot 2024-08-18 at 10 24 16 PM" src="https://github.com/user-attachments/assets/d4363b9c-60dd-433c-aae9-45d9443f70f2">

### Interactive Blockchain Transaction Visualizer 
This tool models transactions as a graph, where each node represents a transaction. The edges have arrows indicating the source of the funds for each transaction. When you click on a node, the graph expands to display the subsequent transactions that occurred using those funds.


https://github.com/user-attachments/assets/3944516d-6b50-40c5-8776-307bdfdffb2e




### Bitcoin PCAP Decoder
To make a transaction, a Bitcoin node creates a transaction message and sends it to its connected peers. This message propagates through the entire P2P network, where each peer verifies it before a miner adds it to the blockchain. By tracking the first node that relays a new, unique transaction ID, we can potentially identify the source of that transaction, exploiting Bitcoin's gossip protocol. By connecting to all nodes in the network and monitoring their transaction relays, it's possible to de-anonymize the blockchain and reveal the true identities behind transactions. This tool helps to do this.

To run this tool, first connect to all the peers in the Bitcoin network and start packet capturing. The captured packets are then given as input to the tool, which decodes the packets, and the output can be either stored in a database or written to a CSV file.

### Online Wallet Search
This tool identifies whether a wallet address is found on any forums, websites, or other online platforms.

## Project Setup
The code is split into frontend and backend

### To run the backend 
1. Navigate to the `backend` folder
2. Execute `pip install -r requirements.txt`
3. Run the backend `python3 app.py`

### To run the frontend
1. Navigate to the `frontend` folder
2. Execute `npm install`
3. Run the frontend `npm start`

## Prerequisite
This Project uses blockcypher API for fetching the blockchain data, therefore one must register it and create a .env file with it in the `Bitcoin-Investigation-Tool/backend/` directory.
```
API_KEY=YOUR_API_KEY
```

## Using the Tools
### Interactive Blockchain Transaction Visualizer 
This tool is available on the website. Enter the transaction ID you want to investigate, and it will generate the graph.

### Bitcoin PCAP Decoder
To use this tool 
1. Navigate to `Bitcoin-Investigation-Tool/backend/capture` and drop the capture file to analyse in this directory
1. Navigate to `Bitcoin-Investigation-Tool/backend/tool_pcapanalyzer/`  
2. Run `python3 extractip.py`

### Online Wallet Search
To use this tool
1. Open to `Bitcoin-Investigation-Tool/backend/tool_webscrapper/links.txt` and paste the links you want to scrap from
2. Run `python3 scrap.py` 
3. Open the website and search the wallet you want to find

Steps 1 and 2 are a one-time process and do not need to be repeated unless new links need to be added.
