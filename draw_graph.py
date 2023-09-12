import networkx as nx
import matplotlib.pyplot as plt

DG = nx.DiGraph()

def create_node(parent_tx,child_tx,graph):

    if parent_tx not in DG:
        graph.add_node(parent_tx)
    if child_tx not in DG:
        graph.add_node(child_tx)

    graph.add_edge(parent_tx,child_tx)
