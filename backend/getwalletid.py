import hashlib 
import base58
from bitcoin import *

def classify_script(decoded_script):
    # OP_DUP OP_HASH160 <20 byte Public KeyHash> OP_EQUAL OP_CHECKSIG
    if len(decoded_script) == 5 and decoded_script[0] == 118 and decoded_script[1] == 169 and (decoded_script[-2] == 135 or decoded_script[-2] == 136) and decoded_script[-1] == 172:
        return "p2pkh"
    #OP_HASH160 [20-byte-hash-value] OP_EQUAL
    elif len(decoded_script) == 3 and decoded_script[0] == 169 and (decoded_script[-1] == 135 or decoded_script[-1] == 136):
        return "p2sh"
    else:
        return "unknown"

def get_address(script , prefix, flag):

    script = script.replace(":","")
    public_key = ""
    if(flag):
        sig, public_key = deserialize_script(script)
    else:
        script = deserialize_script(script)
        scripttype = classify_script(script)
        if(scripttype=="p2pkh"):
            public_key=script[2]
            sha1=hashlib.sha256(bytes.fromhex(prefix+public_key))
            sha2 = hashlib.sha256(bytes.fromhex(sha1.hexdigest()))
            checksum= sha2.hexdigest()[0:8]
            address = prefix +  public_key + checksum
            address=base58.b58encode(bytes.fromhex(address)).decode('utf-8')
            return address
        else:
            return scripttype

    '''
    length_in_string = script[:2]
    length_in_hex = int(length_in_string, 16)
    length_in_chars = length_in_hex * 2 #66 chars

    signature = script[2:length_in_chars+2]

    length_in_string = script[length_in_chars+2:length_in_chars+4]

    public_key = script[length_in_chars + 4:]
    '''
    sha=hashlib.sha256(bytes.fromhex(public_key))
    
    #r=RIPEMD160.new()
    r=hashlib.new('ripemd160',(bytes.fromhex(sha.hexdigest())))
    #r.update(bytes.fromhex(sha.hexdigest()))

    #ripemd160_script = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    r = r.hexdigest()

    extended_public_key= prefix+ r


    sha1 = hashlib.sha256(bytes.fromhex(extended_public_key))
    sha2 =hashlib.sha256(bytes.fromhex(sha1.hexdigest()))

    checksum=sha2.hexdigest()[0:8]

    addr_in_hex=extended_public_key+checksum
    #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')
    return address
