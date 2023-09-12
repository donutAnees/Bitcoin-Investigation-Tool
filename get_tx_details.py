import requests

def get_transaction_info(transaction_id):
    response = requests.get("https://api.blockcypher.com/v1/btc/main/txs/" + transaction_id + "?token=cd380b7fda6a44909bff4645ec8b0448")
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

        input_addresses.append(cur_input)

    for i in range (no_of_outputs):

        out_field = response_json.get("outputs", [])
        cur_output = out_field[i]

        output_addresses.append(cur_output)

    with open(input_addr_file , "w+") as file:
        for addr in input_addresses:
            file.write(str(addr) + "\n")
    file.close()

    with open(output_addr_file , "w+") as file:
        for addr in output_addresses:
            file.write(str(addr) + "\n")
    file.close()

get_transaction_info("f854aebae95150b379cc1187d848d58225f3c4157fe992bcd166f58bd5063449")