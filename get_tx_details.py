import requests

def get_transaction_info(transaction_id):
    response = requests.get("https://blockchain.info/rawtx/" + transaction_id )
    response_json = response.json()

    no_of_inputs = response_json["vin_sz"]
    no_of_outputs = response_json["vout_sz"]

    input_addr_file = f'{transaction_id}_input_addr.txt'
    output_addr_file = f'{transaction_id}_output_addr.txt'

    input_addresses = []
    output_addresses = []

    for i in range (no_of_inputs):

        in_field = response_json.get("inputs",[])
        cur_input = in_field[i]
        prev_output = cur_input.get("prev_out", {})
        user_addr = prev_output.get("addr")

        input_addresses.append(user_addr)

    for i in range (no_of_outputs):

        out_field = response_json.get("out", [])
        cur_output = out_field[i]
        output_addr = cur_output.get("addr")

        output_addresses.append(output_addr)

    with open(input_addr_file , "w+") as file:
        for addr in input_addresses:
            file.write(addr + "\n")
    file.close()

    with open(output_addr_file , "w+") as file:
        for addr in output_addresses:
            file.write(addr + "\n")
    file.close()

