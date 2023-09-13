from pyvis.network import Network

import get_tx_details
import draw_graph

tx_id = input()

get_tx_details.get_transaction_info(tx_id)

g = Network(height="1500px", width="75%", bgcolor="#222222", font_color="white", directed=True)
g.show_buttons()
g.set_edge_smooth("dynamic")
# g.set_options(draw_graph.custom_js_code)
g.add_node(tx_id)

draw_graph.draw_edges(g, tx_id, direction='input')
draw_graph.draw_edges(g, tx_id, direction='output')
g.show('graph.html', notebook=False)

