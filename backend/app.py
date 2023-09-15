from flask import Flask , render_template
from flask import request
from flask_cors import CORS
from pyvis.network import Network
import get_graph_details

# import get_tx_details
# import draw_graph



# def returnGraph(tx_id):
#     get_tx_details.get_transaction_info(tx_id)

#     g = Network(height="1500px", width="75%", bgcolor="#222222", font_color="white", directed=True)
#     g.show_buttons()
#     g.set_edge_smooth("dynamic")
#     # g.set_options(draw_graph.custom_js_code)
#     g.add_node(tx_id)

#     draw_graph.draw_edges(g, tx_id, direction='input')
#     draw_graph.draw_edges(g, tx_id, direction='output')
#     g.show('./templates/graph.html', notebook=False)


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