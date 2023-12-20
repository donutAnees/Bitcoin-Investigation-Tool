import os
import pandas as pd

print("enter input and output filenames:")
input, output= input().split()

output_filename=output+'.json'

#the format: os.system("tshark -r path/to/pcap_file.pcap -T fields -e ip.src -e ip.dst -E separator=/t -E occurrence=f > traffic.csv")
# -e frame.time_epoch
#-e frame.time -e frame.time_delta -e frame.time_delta_displayed -e frame.time_relative

cmd = 'tshark -r {}.pcap -T json fields -e ip.dst -e ip.src -e frame.time -e frame.time_epoch -e data.data -E separator=,  | sed \'s/,/ /\' | awk \'{{print $4"-"$1"-"$2}}\' -E header=y > {}.json'

#cmd = 'tshark -r {}.pcap -T json fields -e ip.dst -e ip.src -e frame.time -e frame.time_epoch -e data.data -E separator=,  | ForEach-Object {{ $_ -replace ",", " " }} | awk \'{{print $4"-"$1"-"$2}}\' -E header=y > {}.json'
final_cmd = cmd.format(input, output)
os.system(final_cmd)
'''
df = pd.read_csv(output_filename)
df.to_csv('{}.csv'.format(output), index=False)
'''