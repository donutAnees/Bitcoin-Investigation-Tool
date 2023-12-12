from flask import Flask , render_template
from flask import request
from flask_cors import CORS
from flask_session import Session

import get_graph_details

details_dict = {
    'nodes' : [],
    'edges' : []
}

app = Flask('__name__')
CORS(app)

Session(app)
@app.route('/transactionhash' , methods = ["GET"])
def init():
    hash = request.args.get("hash")
    details_dict['nodes'].append({'id':hash})
    print(details_dict)
    return details_dict

@app.route('/expand' , methods = ["GET"])
def expand():
    node = request.args.get("id")
    new_dict = get_graph_details.get_graph_details(node , details_dict)
    for new_node in new_dict['nodes']:
        details_dict['nodes'].append(new_node)
    for new_edge in new_dict['edges']:
        details_dict['edges'].append(new_edge)

    print(new_dict)
    return new_dict

if __name__ == "__main__":
    app.run(debug=True)