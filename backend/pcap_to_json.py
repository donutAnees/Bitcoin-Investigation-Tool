import os
import json

print("enter input and output filenames:")
input, output= input().split()

output_filename=output+'.json'
cmd ='tshark -r {}.pcapng -T json -e ip.dst -e ip.src -e tcp.srcport -e tcp.dstport -e frame.time -e frame.time_epoch -e tcp.payload -e bitcoin.command -E separator=, -E header=y > {}.json'
#cmd ='tshark -r {}.pcapng -T json -e ip.dst -e ip.src -e frame.time -e frame.time_epoch -e data.data -E separator=, -E header=y > {}.json'
final_cmd = cmd.format(input, output)
os.system(final_cmd)