from flask import Flask , render_template
from flask import request
from flask_cors import CORS

import get_graph_details

details_dict = {
    'nodes' : [],
    'edges' : []
}

app = Flask('__name__')
CORS(app) 

@app.route('/transactionhash' , methods = ["GET"])
def init():
    hash = request.args.get("hash")
    get_graph_details.add_node(hash , details_dict)
    return details_dict

@app.route('/expand' , methods = ["GET"])
def expand():
    node = request.args.get("id")
    get_graph_details.get_graph_details(node , details_dict)
    return details_dict

if __name__ == "__main__":
    app.run(debug=True)