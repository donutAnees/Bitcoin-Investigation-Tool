from flask import Flask, session
from flask import request
from flask_cors import CORS

import os
import pandas as pd
import get_graph_details
import get_tx_details
import get_mixer_nodes
import prediction
import secrets


app = Flask("__name__")
CORS(app)
cors = CORS(app,resources={
    r"/*" : {
        "origins" : "*"
    }
})

secret_key = secrets.token_hex(16)
app.secret_key = secret_key


@app.route("/transactionhash", methods=["GET"])
def init():
    # Define the folder path
    transaction_folder = "./transaction_folder"
    # Check if the folder exists, and create it if it doesn't
    if not os.path.exists(transaction_folder):
        os.makedirs(transaction_folder)

    # If we get a new request, we clear everything we had 
    session['details_dict'] = {"nodes": [], "edges": []}
    hash = request.args.get("hash")
    tx_detail = get_tx_details.get_transaction_info(hash)
    session['details_dict']["nodes"].append(tx_detail)
    return session['details_dict']


@app.route("/expand", methods=["GET"])
def expand():
    node = request.args.get("id")
    details_dict = session.get('details_dict', {"nodes": [], "edges": []})
    new_dict = get_graph_details.get_graph_details(node, details_dict)
    details_dict["nodes"].extend(new_dict["nodes"])
    details_dict["edges"].extend(new_dict["edges"])
    session['details_dict'] = details_dict
    return new_dict


@app.route("/wallet", methods=["GET"])
def getStatus():
    walletID = request.args.get("id")
    status = prediction.results(walletID)
    return {"status": status}


@app.route("/mixers", methods=["GET"])
def getMixers():
    details_dict = session.get('details_dict', {"nodes": [], "edges": []})
    get_mixer_nodes.getMixer(details_dict)
    return details_dict 


@app.route("/walletavail", methods=["GET"])
def getScrap():
    walletInfo = request.args.get("id")
    inputs = pd.read_csv("./tool_webscrapper/output.csv")
    for i in range(len(inputs.index)):
        if (
            inputs["Wallet ID"][i].strip() == walletInfo
        ):  # Use strip() to remove leading/trailing whitespaces
            print(inputs["Website"][i])
            return {"availability": True, "website": inputs["Website"][i]}
    return {"availability": False, "website": None}


if __name__ == "__main__":
    app.run(debug=True)
