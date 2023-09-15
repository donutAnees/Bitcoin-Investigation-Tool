import pandas as pd
import json

import get_tx_details

details_dict = {
    'nodes' : [],
    'edges' : []
}

def add_node(tx_id, details_dict, other=None):
    for node in details_dict['nodes']:
        if node['id']==tx_id:
            break
    else:
        if other:
            info = {'id':tx_id}
            info.update(other)
            details_dict['nodes'].append(info)
        else:
            details_dict['nodes'].append({'id':tx_id})

def add_edge(tx_id1, tx_id2, details_dict):
    details_dict['edges'].append({'from':tx_id1, 'to':tx_id2})

def get_graph_details(tx_id, details_dict):

    add_node(tx_id, details_dict)
        
    get_tx_details.get_transaction_info(tx_id)

    inputs = pd.read_csv("./transaction_folder/"+tx_id+'_input_addr.csv')
    for i in range(len(inputs.index)):
        id = inputs['prev_hash'][i]
        if id:
            other = {
                'in_output_index': int(inputs['output_index'][i]),
                'in_script': inputs['script'][i], 
                'in_output_value': int(inputs['output_value'][i]), 
                'in_sequence': int(inputs['sequence'][i]), 
                'in_addresses': inputs['addresses'][i],
                'in_script_type': inputs['script_type'][i], 
                'in_age': int(inputs['age'][i])
            }
            add_node(id, details_dict, other)
            add_edge(id, tx_id, details_dict)

    outputs = pd.read_csv("./transaction_folder/"+tx_id+'_output_addr.csv')
    for i in range(len(outputs.index)):
        id = outputs['spent_by'][i]
        if id:
            other = {
                'out_value': int(outputs['value'][i]),
                'out_script': outputs['script'][i],
                'out_addresses': outputs['addresses'][i],
                'out_script_type': outputs['script_type'][i]
            }
            add_node(id, details_dict, other)
            add_edge(id, tx_id, details_dict)
    
    return details_dict

with open('graph_details.json','w') as f:
    json.dump(get_graph_details('f854aebae95150b379cc1187d848d58225f3c4157fe992bcd166f58bd5063449', details_dict),f)




        

