import pandas as pd
import get_tx_details

def add_node(tx_id, details_dict, other):
    nodes = []
    if (tx_id not in details_dict['nodes']):
        details = get_tx_details.get_transaction_info(tx_id)
        node = {'id': tx_id, 'title': {
            'details': details,
            'other': other,
        }}
        nodes.append(node)
    return nodes


def add_edge(tx_id1, tx_id2, details_dict):
    edges = []
    edge = {'source': tx_id1, 'target': tx_id2}
    if (edge not in details_dict['edges']):
        edges.append({'source': tx_id1, 'target': tx_id2})
    return edges


def get_graph_details(tx_id, details_dict):
        
        nodes = []
        edges = []

        inputs = pd.read_csv("./transaction_folder/"+tx_id+'_input_addr.csv')
        for i in range(len(inputs.index)):
            id = inputs['prev_hash'][i]
            if not pd.isna(id):
                other = {
                    'in_output_index': int(inputs['output_index'][i]),
                    'in_script': inputs['script'][i],
                    'in_output_value': int(inputs['output_value'][i]),
                    'in_sequence': int(inputs['sequence'][i]),
                    'in_addresses': inputs['addresses'][i],
                    'in_script_type': inputs['script_type'][i],
                    'in_age': int(inputs['age'][i])
                }

                nodes += add_node(id, details_dict, other)
                edges += add_edge(id, tx_id, details_dict)

        outputs = pd.read_csv("./transaction_folder/"+tx_id+'_output_addr.csv')
        for i in range(len(outputs.index)):
            id = outputs['spent_by'][i]
            if not pd.isna(id):
                other = {
                    'out_value': int(outputs['value'][i]),
                    'out_script': outputs['script'][i],
                    'out_addresses': outputs['addresses'][i],
                    'out_script_type': outputs['script_type'][i]
                }
                nodes += add_node(id, details_dict, other)
                edges += add_edge(tx_id, id, details_dict)

        
        return {'nodes': nodes, 'edges': edges}
