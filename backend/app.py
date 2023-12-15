from flask import Flask , render_template
from flask import request
from flask_cors import CORS

import get_graph_details
import get_tx_details
import get_mixer_nodes

#cant risk api calls so made sure to only read from the files, commented stuff should be uncommented during production 

details_dict = {
    'nodes' : [],
    'edges' : []
}

app = Flask('__name__')
CORS(app) 

@app.route('/transactionhash' , methods = ["GET"])
def init():
    hash = request.args.get("hash")
    tx_detail = get_tx_details.get_transaction_info(hash)
    details_dict['nodes'].append(tx_detail)
    return details_dict

@app.route('/expand' , methods = ["GET"])
def expand():
    node = request.args.get("id")
    new_dict = get_graph_details.get_graph_details(node , details_dict)
    for new_node in new_dict['nodes']:
        details_dict['nodes'].append(new_node)
    for new_edge in new_dict['edges']:
        details_dict['edges'].append(new_edge)
    return new_dict

@app.route('/wallet' , methods = ['GET'])
def getStatus():
    walletID = request.args.get("id")
    status = 'illegal'
    return {'status' : status}

@app.route('/mixers' , methods = ['GET'])
def getMixers():
    get_mixer_nodes.getMixer(details_dict)
    return details_dict

if __name__ == "__main__":
    app.run(debug=True)