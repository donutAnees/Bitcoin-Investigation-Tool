import base58
from hashlib import sha256 
from Crypto.Hash import RIPEMD160 

def get_address(hash , version):
    length_in_string = hash[:2]
    length_in_hex = int(length_in_string, 16)
    length_in_chars = length_in_hex * 2 # 66 chars

    signature = hash[2:length_in_chars+2]

    length_in_string = hash[length_in_chars+2:length_in_chars+4]

    public_key = hash[length_in_chars + 4:]

    print(public_key)

    sha=sha256(bytes.fromhex(public_key))
    
    r=RIPEMD160.new()
    r.update(bytes.fromhex(sha.hexdigest()))

    #ripemd160_hash = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    r = r.hexdigest()

    # version= '0'
    extended_public_key= version+ r

    print(extended_public_key)


    sha1 = sha256(bytes.fromhex(extended_public_key))
    sha2 =sha256(bytes.fromhex(sha1.hexdigest()))
    print(sha2)

    checksum=sha2.hexdigest()[0:8]
    print(checksum)


    addr_in_hex=extended_public_key+checksum
    print(addr_in_hex)
    # #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')    
    return address
