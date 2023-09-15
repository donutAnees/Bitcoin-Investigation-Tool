from flask import Flask , render_template
from flask import request
from flask_cors import CORS
from pyvis.network import Network
import get_tx_details
import draw_graph


def returnGraph(tx_id):
    get_tx_details.get_transaction_info(tx_id)

    g = Network(height="1500px", width="75%", bgcolor="#222222", font_color="white", directed=True)
    g.show_buttons()
    g.set_edge_smooth("dynamic")
    # g.set_options(draw_graph.custom_js_code)
    g.add_node(tx_id)

    draw_graph.draw_edges(g, tx_id, direction='input')
    draw_graph.draw_edges(g, tx_id, direction='output')
    g.show('./templates/graph.html', notebook=False)


app = Flask('__name__')
CORS(app) 

@app.route('/transactionhash' , methods = ["GET"])
def greet():
    hash = request.args.get("hash")
    #returnGraph(hash)
    return render_template('graph.html')

if __name__ == "__main__":
    app.run(debug=True)