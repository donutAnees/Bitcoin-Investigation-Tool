import os
import pandas as pd

print("enter input and output filenames:")
input, output= input().split()

output_filename=output+'.csv'

cmd ='tshark -r {}.pcap -T json -e ip.dst -e ip.src -e frame.time -e frame.time_epoch -e data.data -E separator=, -E header=y > {}.json'
final_cmd = cmd.format(input, output)
os.system(final_cmd)