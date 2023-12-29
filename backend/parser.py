#get_address("473044022001bbb98ef9070d68ab34d2402becf21c6a728f138f550cba358f6f5631c6bf300220450b4ae16a45217cb8c2d43929b9c3968c065c30e1bc5caf6ebfb2e48aac079101210308d8aff8763b126a66bb4192cc5d4c63bb3d7c471cd8c20b270a609090e86a3a", "01")
#get_address("eb32f14fb4458bbfa5184ba1dd53b64b08cbdb60710e7aec29ce04c029f50594", "01")

#get_address("473044022100edf664ebfc12a3998d242fbdd8a1a44c13e4e7f6d7dbddde9ae5610bfd2c9c38021f74ec1e2eca7310baa17c60cbaaffa0503cee680f13fd9a10fd04f2910958c9012103486669962008e0713660b6d69117a65fcecd221d06c1e5077b4d9cd477c0cf98", "01")

import base58
from hashlib import sha256
from Crypto.Hash import RIPEMD160

def get_address(public_key , version):
    '''
    length_in_string = script[:2]
    length_in_hex = int(length_in_string, 16)
    length_in_chars = length_in_hex * 2 #66 chars

    signature = script[2:length_in_chars+2]

    length_in_string = script[length_in_chars+2:length_in_chars+4]

    public_key = script[length_in_chars + 4:]
    '''
    print(public_key)
    sha=sha256(bytes.fromhex(public_key))
    
    r=RIPEMD160.new()
    r.update(bytes.fromhex(sha.hexdigest()))

    #ripemd160_script = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    r = r.hexdigest()

    # version= '0'# ??????????????????????????????????????????????????????????????????????????????????????????????????
    extended_public_key= version+ r

    print(extended_public_key)


    sha1 = sha256(bytes.fromhex(extended_public_key))
    sha2 =sha256(bytes.fromhex(sha1.hexdigest()))
    print(sha2)

    checksum=sha2.hexdigest()[0:8]
    print(checksum)


    addr_in_hex=extended_public_key+checksum
    print(addr_in_hex)
    #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')
    return address


pub_key="76:a9:14:fe:fb:a2:86:73:e6:e4:bd:72:12:00:c0:bd:b4:cc:37:1a:57:c3:b7:88:ac".replace(":","")
addr=get_address(pub_key,"00")

print("bitcoin addr:", addr)