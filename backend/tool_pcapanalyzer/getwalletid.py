import hashlib 
import base58
import bech32
import binascii
from bitcoin import *

# Function to classify the type of script based on its opcodes
def classify_script(decoded_script):
    # OP_DUP OP_HASH160 <20 byte Public KeyHash> OP_EQUAL OP_CHECKSIG
    if len(decoded_script) == 5 and decoded_script[0] == 118 and decoded_script[1] == 169 and (decoded_script[-2] == 135 or decoded_script[-2] == 136) and decoded_script[-1] == 172:
        return "p2pkh"
    #OP_HASH160 [20-byte-hash-value] OP_EQUAL
    elif len(decoded_script) == 3 and decoded_script[0] == 169 and (decoded_script[-1] == 135 or decoded_script[-1] == 136):
        return "p2sh"
    #OP_0 OP_PUSHBYTES_20 [20-byte-hash-value]
    elif len(decoded_script) == 2 and decoded_script[0] == None:
        return "p2wpkh"
    else:
        return "unknown"

def get_address(script, flag):
    #flag is determine if the function is called by an output script or input script 
    prefix = "00"
    script = script.replace(":","")
    public_key = ""
    if(flag):
    #for input script, consists of the signature and the public key
        try:
            script = deserialize_script(script) # this function deserializes a script into signature and the public key
            public_key = script[1] # extracting the public key
        except:
            return "error"                                                                                                                 
        # converting the public key into wallet address
        sha=hashlib.sha256(bytes.fromhex(public_key))
        r=hashlib.new('ripemd160',(bytes.fromhex(sha.hexdigest())))
        r = r.hexdigest()
        extended_public_key= prefix+ r
        sha1 = hashlib.sha256(bytes.fromhex(extended_public_key))
        sha2 =hashlib.sha256(bytes.fromhex(sha1.hexdigest()))
        checksum=sha2.hexdigest()[0:8]
        addr_in_hex=extended_public_key+checksum
        address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')
        return address # return the wallet address
    
    else:
    #for output script, defines the conditions that must be met to unlock and spend Bitcoins from a transaction output, consists of OPCODE along with the wallet address
        deserializedscript = deserialize_script(script) # this function deserialized the script into OPCODES and the public key
        scripttype = classify_script(deserializedscript) # based on the opcode, the wallet type is determined and the wallet adderss is returned
        if(scripttype=="p2pkh"):
            public_key=deserializedscript[2]
        elif(scripttype == "p2sh"):
            prefix = "05"
            public_key = deserializedscript[1]
        elif(scripttype == "p2wpkh"):
            public_key = deserializedscript[1]
            public_key = binascii.unhexlify(public_key)
            bech32_address = bech32.encode('bc',0,public_key)
            return bech32_address
        else:
            return scripttype
        sha1=hashlib.sha256(bytes.fromhex(prefix+public_key))
        sha2 = hashlib.sha256(bytes.fromhex(sha1.hexdigest()))
        checksum= sha2.hexdigest()[0:8]
        address = prefix +  public_key + checksum
        address=base58.b58encode(bytes.fromhex(address)).decode('utf-8')
        return address # returns the wallet address


