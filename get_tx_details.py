import requests
import pandas as pd

def get_transaction_info(transaction_id):
    response = requests.get("https://api.blockcypher.com/v1/btc/main/txs/" + transaction_id + "?token=cd380b7fda6a44909bff4645ec8b0448")
    response_json = response.json()

    no_of_inputs = response_json["vin_sz"]
    no_of_outputs = response_json["vout_sz"]

    input_addr_file = f'{transaction_id}_input_addr.csv'
    output_addr_file = f'{transaction_id}_output_addr.csv'

    input_addresses = []
    output_addresses = []

    for i in range (no_of_inputs):

        in_field = response_json.get("inputs",[])
        cur_input = in_field[i]

        input_addresses.append(cur_input)

    for i in range (no_of_outputs):

        out_field = response_json.get("outputs", [])
        cur_output = out_field[i]

        output_addresses.append(cur_output)

    prev_hash = []
    output_index = []
    script = []
    output_value = []
    sequence = []
    addresses = []
    script_type = []
    age = []

    for i in input_addresses:
        prev_hash.append(i["prev_hash"])
        output_index.append(i["output_index"])
        script.append(i["script"])
        output_value.append(i["output_value"])
        sequence.append(i["sequence"])
        addresses.append(i["addresses"])
        script_type.append(i["script_type"])
        age.append(i["age"])

    input_dict = {
        'prev_hash': prev_hash,
        'output_index': output_index,
        'script': script,
        'output_value': output_value,
        'sequence': sequence,
        'addresses': addresses,
        'script_type': script_type,
        'age': age
    }

    df = pd.DataFrame(input_dict)
    df.to_csv(input_addr_file,index=False)
    
    value = []
    script = []
    spent_by = []
    addresses = []
    script_type = []

    for item in output_addresses:
        value.append(item['value'])
        script.append(item['script'])
        spent_by.append(item['spent_by'])
        addresses.append(item['addresses'])
        script_type.append(item['script_type'])

    output_dict = {
        'value': value,
        'script': script,
        'spent_by': spent_by,
        'addresses': addresses,
        'script_type': script_type
    }

    df = pd.DataFrame(output_dict)
    df.to_csv(output_addr_file,index=False)


get_transaction_info("f854aebae95150b379cc1187d848d58225f3c4157fe992bcd166f58bd5063449")