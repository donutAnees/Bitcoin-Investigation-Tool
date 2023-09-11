import requests
import pandas as pd


with open('user_transaction_ids', 'r') as tx_file:
    lines = tx_file.readlines()


data = []


input_data = []
input_count = 0

flag = 0

no_input = 0
no_output = 0

for line in lines:
    
    if flag == 0:
        no_input = line.split()
        flag = 1
        continue

    stripped_line = line.strip()


    if stripped_line == "end of input":
        
        if input_data:
            input_filename = f'input_{input_count}.csv'
            df = pd.DataFrame(input_data, columns=["Transaction ID", "Inputs", "Outputs"])
            table_format = df.to_string(index=False, justify='center')
            with open(input_filename, "w") as file:
                file.write(table_format)
        
        
        input_data = []
        input_count += 1

    else:
        try:
            response = requests.get("https://blockchain.info/rawtx/" + stripped_line)

            
            if response.status_code == 404:
                print(f"Transaction {stripped_line} not found.")
                continue  

            response.raise_for_status() 
            response_json = response.json()

            
            if 'vin_sz' in response_json:
                no_in = response_json["vin_sz"]
            else:
                no_in = "N/A"  

            no_out = response_json.get("vout_sz", "N/A")  

            
            input_data.append({
                "Transaction ID": stripped_line,
                "Inputs": no_in,
                "Outputs": no_out
            })
            df = pd.DataFrame(data)
            
        except requests.exceptions.HTTPError as e:
            print(f"Error fetching transaction {stripped_line}: {e}")
        except Exception as e:
            print(f"Error processing transaction {stripped_line}: {e}")

print("CSV files for each input have been created.")




        
    
