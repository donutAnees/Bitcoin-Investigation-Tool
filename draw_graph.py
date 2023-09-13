from pyvis.network import Network
from flask import Flask, request
import pandas as pd

import get_tx_details

# app = Flask(__name__)

def draw_edges(graph, tx_id, direction):
    no_of_nodes = len(graph.get_nodes())
    if direction == 'input':
        df = pd.read_csv(tx_id+'_input_addr.csv')
        value = 'prev_hash'
    else:
        df = pd.read_csv(tx_id+'_output_addr.csv')
        value = 'spent_by'
    for i in range(len(df.index)):
        node = df[value][i]
        for node_label in graph.get_nodes():
            if node_label == node:
                break
        else:
            graph.add_node(node)
            get_tx_details.get_transaction_info(node)
            if direction == 'input':
                graph.add_edge(node, tx_id)
            else:
                graph.add_edge(tx_id, node)

# @app.route('/',methods=['POST'])
# def click_node():
#     data = request.json
#     node_id = data[node_id]
#     draw_edges(graph, tx_id, node_id, direction='input')
#     draw_edges(graph,tx_id, node_id, direction='output')

# if __name__ == '__main__':
#     app.run()

# custom_js_code = """
# function handleNodeClick(nodeId){

# }
# """
