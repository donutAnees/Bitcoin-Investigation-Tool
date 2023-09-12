import networkx as nx
import matplotlib.pyplot as plt

DG = nx.DiGraph()

def create_node(parent_tx,child_tx):

    if parent_tx not in DG:
        DG.add_node(parent_tx)
    if child_tx not in DG:
        DG.add_node(child_tx)

    DG.add_edge(parent_tx,child_tx)

    nx.spring_layout(DG)
