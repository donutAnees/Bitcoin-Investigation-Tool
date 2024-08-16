import hashlib

''' 

This program is used to convert a deserialized transaction data in JSON format back to raw hex data, which is then used to find the txid

Each non segwit transaction needs the following fields

    1. version // 4 byte 01 00 00 00 
    2. input count // 1+ bytes reverse
    3. # for each input
        1. previous output hash (already reversed) // 36 bytes 
        2. previous output index // 4 bytes reverse
        3. script length // 1+ var_int length reverse
        4. sig script
        5. sequence // 4 byte - FF FF FF FF
    4. output count // 1+ var_int bytes
    5. # for each output
        1. value // 8 bytes reverse
        2. script length // 1+ var_int length reverse
        3. out script
    6. locktime // 4 bytes reverse

Each segwit transaction needs the following fields

    1. version // 4 byte 02 00 00 00
    2. witness flag - 00 01 // 2 bytes
    3. input count 
    4. # for each input
        1. previous output hash (already reversed) // 36 bytes 
        2. previous output index // 4 bytes reverse
        3. script length // 00 since script is present in the witness part
        4. sequence // 4 byte - FD FF FF FF
     5. # for each output
        1. value // 8 bytes reverse
        2. script length // 1+ var_int length reverse
        3. out script
    6. lockdown // 4 bytes reverse
    7. witness part

    we dont need the witness part to generate the transaction id so we neglect this field


    TXIDs have two forms; the form used internally for outpoints and merkle leaves (internal byte order), and the form used in RPC calls and block explorers (RPC byte order). 

    For variable int
    Value	                    Storage                                     length
    <  0xFD	 	                uint8_t(No need to prepend)                 1 byte
    <= 0xFFFF	                0xFD followed by the length as uint16_t     3 bytes
    <= 0xFFFF FFFF		        0xFE followed by the length as uint32_t     5 bytes
    -	      	                0xFF followed by the length as uint64_t     9 bytes
    
    Prepend value with these prefixes if they fall into any of category, these are escape characters which help bitcoin nodes know how many bytes are occupied for the length

    Refer the following documentation for the transaction fields detailed explanation 

    https://en.bitcoin.it/wiki/Protocol_documentation#tx

'''


# This function is used to reverse an hex, each 2 characters represent one byte, we reverse the hex string byte by byte( 2 characters )
# example: fe 45 69 01, this will be reversed as 01 69 45 fe
def reverseHex(hex):
    if(len(hex)==2):
        return hex
    bytes_list = [hex[i:i+2] for i in range(0, len(hex), 2)]
    reversed_hex_string = ''.join(bytes_list[::-1])
    return reversed_hex_string

# This function deals with removing the 0x prefix from the hex( since python prepends 0x to hex values ) and if the hex is odd prepends a 0 to make the string even since each byte is 2 character
def fixHex(hex):
  if(len(hex)%2!=0):
      return "0" + hex[2:]
  else:
      return hex[2:]
  
# This the function which prepends the required prefix to the var int value, consider the input value 256 in hexadecimal this will be 0x12c
# since this hex is of odd length we will append it with a zero therefore it will be 01 2c( we removed the 0x since we dont need it )
# using the table above the value is < 0XFD <= 0XFFFF, therefore we append it with FD after reversing the value(since bitcoin transaction expects the hex value to be reversed), which gives the final result of FD 2C 01
def handleVarInt(value):
    if(value < 253):
        return ""
    if(value <= 65535):
        return "FD"
    if(value <= 4294967295):
        return "FE"
    return "FF"

#This is the main function which decodes the transaction in JSON format
def decodeJSONBitcoinPayload(transaction):

    #The version number of the transaction this can be 1 or 2
    version = "0" + transaction["bitcoin.tx.version"] + "000000"

    #We use these two variables to find the required prefix for the input and output count respectively
    inputPrefix = handleVarInt(int(transaction["bitcoin.tx.input_count"]))
    outputPrefix = handleVarInt(int(transaction["bitcoin.tx.output_count"]))

    #The input count and output count determines the number of input and output wallets respectively
    inputCount = hex(int(transaction["bitcoin.tx.input_count"])) 
    inputCount = inputPrefix+reverseHex(fixHex(inputCount)) # prefix is appended

    outputCount = hex(int(transaction["bitcoin.tx.output_count"]))
    outputCount = outputPrefix+reverseHex(fixHex(outputCount)) # prefix is appended

    # This field contains the transaction input data
    bitcoinTxIn = transaction["bitcoin.tx.in"]
    if (isinstance(bitcoinTxIn, list) == False): # if the input has only one input, then it will be inside {}, our function expects a list [] therefore we explicitly convert a dictionary to a list
        bitcoinTxIn = [bitcoinTxIn]
    
    #This field contains the transaction output data
    bitcoinTxOut = transaction["bitcoin.tx.out"]
    if (isinstance(bitcoinTxOut,list) == False): 
        bitcoinTxOut = [bitcoinTxOut]

    #This field is used for scheduling transactions
    lockTime = hex(int(transaction["bitcoin.tx.lock_time"]))
    lockTimePrefixZeroes = 8 - len(lockTime[2:]) # we remove the first two characters, i.e 0x and find the number of 0's to be prepended to make the field 8 cahracters long
    lockTime = "0" * lockTimePrefixZeroes + lockTime[2:]
    lockTime = reverseHex(lockTime)

    inTx = ""
    # This loop iterates through each input and gets the required fields such as prev output hash and index, sigscript length, sigscript and the sequence number
    for tx in bitcoinTxIn:
        # Extract previous output hash (removing colons for formatting):
        prevOutputHash = tx["bitcoin.tx.in.prev_output"]["bitcoin.tx.in.prev_output.hash"]
        prevOutputHash = prevOutputHash.replace(":","")

        # Extract previous output index (formatting as 8-byte hex string):
        prevOutputIndex = hex(int(tx["bitcoin.tx.in.prev_output"]["bitcoin.tx.in.prev_output.index"]))
        prevOutputIndexPrefixZeroes = 8 - len(prevOutputIndex[2:]) # Calculate needed zeros
        prevOutputIndex = "0" * prevOutputIndexPrefixZeroes + str(prevOutputIndex[2:]) # prepend needed zeroes
        prevOutputIndex = reverseHex(prevOutputIndex)

        # Extract signature script length (formatting as hex string):
        sigscriptLength = hex(int(tx["bitcoin.tx.in.script_length"]))
        sigscriptLength = reverseHex(fixHex(sigscriptLength))

        # Extract signature script (removing colons for formatting):
        scriptSeq = tx["bitcoin.tx.in.sig_script"]
        scriptSeq = scriptSeq.split(":")
        scriptSeq = ''.join(scriptSeq[:])

        # Extract sequence number (formatting as hex string):
        sequence = reverseHex(fixHex(hex(int(tx["bitcoin.tx.in.seq"]))))

        # Concatenate all extracted fields to build the input transaction string:
        inTx += str(prevOutputHash) + str(prevOutputIndex) + str(sigscriptLength) + str(scriptSeq) + str(sequence) 
    
    outTx = ""
    for tx in bitcoinTxOut:
        # Extract output value:
        outValue = hex(int(tx["bitcoin.tx.out.value"]))
        
        # Format output value as 16-byte hexadecimal string:
        outValue = outValue[2:] 
        outValuePrefixZeroes = 16 - len(outValue) # Calculate number of leading zeros needed
        outValue = "0" * outValuePrefixZeroes + str(outValue) # Prepend zeros to reach 16 bytes
        outValue = reverseHex(outValue)
        
        # Extract script length (formatting as hex string):
        scriptLength = hex(int(tx["bitcoin.tx.out.script_length"]))
        scriptLength = reverseHex(fixHex(scriptLength))

        # Extract script (removing colons for formatting):
        script = tx["bitcoin.tx.out.script"]
        script = script.split(":")
        script = ''.join(script[:])

        # Concatenate all extracted fields to build the output transaction string:
        outTx += str(outValue) + str(scriptLength) + str(script)

    rawHex = version + inputCount + inTx + outputCount + outTx + lockTime 

    #returns the txid which is the sha256(sha256(rawHex)), this is reversed since Blockexplorers use the reversed format
    # print(reverseHex(hashlib.sha256(bytes.fromhex(hashlib.sha256(bytes.fromhex(rawHex)).hexdigest())).hexdigest()))
    return reverseHex(hashlib.sha256(bytes.fromhex(hashlib.sha256(bytes.fromhex(rawHex)).hexdigest())).hexdigest())