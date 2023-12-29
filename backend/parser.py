import base58
from hashlib import sha256
import hashlib

def get_address(public_key , version):

    public_key = public_key.replace(":","")
    '''
    length_in_string = script[:2]
    length_in_hex = int(length_in_string, 16)
    length_in_chars = length_in_hex * 2 #66 chars

    signature = script[2:length_in_chars+2]

    length_in_string = script[length_in_chars+2:length_in_chars+4]

    public_key = script[length_in_chars + 4:]
    '''
    sha=sha256(bytes.fromhex(public_key))
    
    #r=RIPEMD160.new()
    r=hashlib.new('ripemd160',(bytes.fromhex(sha.hexdigest())))
    #r.update(bytes.fromhex(sha.hexdigest()))

    #ripemd160_script = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    r = r.hexdigest()

    extended_public_key= version+ r


    sha1 = sha256(bytes.fromhex(extended_public_key))
    sha2 =sha256(bytes.fromhex(sha1.hexdigest()))

    checksum=sha2.hexdigest()[0:8]

    addr_in_hex=extended_public_key+checksum
    #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')
    return address
