import requests
import pandas as pd


def get_transaction_info(transaction_id):
    response = requests.get(
        "https://api.blockcypher.com/v1/btc/main/txs/"
        + str(transaction_id)
    )
    response_json = response.json()

    no_of_inputs = response_json["vin_sz"]
    no_of_outputs = response_json["vout_sz"]

    input_addr_file = f"{transaction_id}_input_addr.csv"
    output_addr_file = f"{transaction_id}_output_addr.csv"

    input_addresses = []
    output_addresses = []

    next_io = False

    if "next_outputs" in response_json or "next_inputs" in response_json:
        next_io = True

    if next_io == True:
        response = requests.get(
            "https://api.blockcypher.com/v1/btc/main/txs/"
            + transaction_id
            + str(max(no_of_inputs, no_of_outputs))
        )
        response_json = response.json()

    for i in range(no_of_inputs):
        in_field = response_json.get("inputs", [])
        cur_input = in_field[i]

        input_addresses.append(cur_input)

    for i in range(no_of_outputs):
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
        if "prev_hash" not in i:
            prev_hash.append(None)
        else:
            prev_hash.append(i["prev_hash"])
        output_index.append(i["output_index"])
        script.append(i["script"])
        output_value.append(i["output_value"])
        sequence.append(i["sequence"])
        addresses.append(i["addresses"])
        script_type.append(i["script_type"])
        age.append(i["age"])

    input_dict = {
        "prev_hash": prev_hash,
        "output_index": output_index,
        "script": script,
        "output_value": output_value,
        "sequence": sequence,
        "addresses": addresses,
        "script_type": script_type,
        "age": age,
    }

    df = pd.DataFrame(input_dict)
    df.to_csv("./transaction_folder/" + input_addr_file, index=False)

    value = []
    script = []
    spent_by = []
    addresses = []
    script_type = []

    for item in output_addresses:
        value.append(item["value"])
        script.append(item["script"])
        if "spent_by" not in item:
            spent_by.append(None)
        else:
            spent_by.append(item["spent_by"])
        addresses.append(item["addresses"])
        script_type.append(item["script_type"])

    output_dict = {
        "value": value,
        "script": script,
        "spent_by": spent_by,
        "addresses": addresses,
        "script_type": script_type,
    }

    df = pd.DataFrame(output_dict)
    df.to_csv("./transaction_folder/" + output_addr_file, index=False)

    tx_detail = {
        "blockheight": response_json["block_height"],
        "total": response_json["total"],
        "inputs": response_json["vin_sz"],
        "outputs": response_json["vout_sz"],
        "id": transaction_id,
        "output_address": output_dict["addresses"],
        "input_address": input_dict["addresses"],
    }

    # df = pd.DataFrame(tx_detail, index=[0])
    # df.to_csv("./transaction_folder/" + transaction_id, index=False)

    return tx_detail


# get_transaction_info("f854aebae95150b379cc1187d848d58225f3c4157fe992bcd166f58bd5063449")
