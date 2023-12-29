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

    sha=sha256(bytes.fromhex(public_key))
    
    r=RIPEMD160.new()
    r.update(bytes.fromhex(sha.hexdigest()))

    #ripemd160_hash = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    r = r.hexdigest()

    # version= '0'
    extended_public_key= version + r

    sha1 = sha256(bytes.fromhex(extended_public_key))
    sha2 =sha256(bytes.fromhex(sha1.hexdigest()))

    checksum=sha2.hexdigest()[0:8]

    addr_in_hex=extended_public_key+checksum

    # #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')    
    
    print(address)

get_address("473044022001bbb98ef9070d68ab34d2402becf21c6a728f138f550cba358f6f5631c6bf300220450b4ae16a45217cb8c2d43929b9c3968c065c30e1bc5caf6ebfb2e48aac079101210308d8aff8763b126a66bb4192cc5d4c63bb3d7c471cd8c20b270a609090e86a3a", "1")
