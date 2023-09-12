import networkx as nx
import matplotlib.pyplot as plt

DG = nx.petersen_graph()

def create_node(parent_tx,child_tx):

    if parent_tx not in DG:
        DG.add_node(parent_tx)
    if child_tx not in DG:
        DG.add_node(child_tx)

    DG.add_edge(parent_tx,child_tx)

    nx.spring_layout(DG)


    pos = nx.spring_layout(DG)
    nx.draw_networkx_nodes(DG, pos, cmap=plt.get_cmap('jet'), 
                         node_size = 500)
    nx.draw_networkx_labels(DG, pos)
    nx.draw_networkx_edges(DG, pos,  edge_color='r', arrows=True)
    nx.draw_networkx_edges(DG, pos, arrows=False)
    plt.show()

create_node(1,2)