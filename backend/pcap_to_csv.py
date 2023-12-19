import os
import pandas as pd

print("enter input and output filenames:")
input, output= input().split()

output_filename=output+'.csv'

#the format: os.system("tshark -r path/to/pcap_file.pcap -T fields -e ip.src -e ip.dst -E separator=/t -E occurrence=f > traffic.csv")

cmd="tshark -r {}.pcapng -T fields -e ip.dst -e ip.src > {}.csv"
final_cmd = cmd.format(input, output)
os.system(final_cmd)
df = pd.read_csv(output_filename)
df.to_csv('{}.csv'.format(output), index=False)