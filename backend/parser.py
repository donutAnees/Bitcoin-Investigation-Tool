import hashlib
import base58
from Crypto.Hash import RIPEMD160, SHA256

def get_address(hash):
    length_in_string = hash[:2]
    length_in_hex = int(length_in_string, 16)
    length_in_chars = length_in_hex * 2 # 66 chars

    signature = hash[2:length_in_chars+2]
    print(signature)

    length_in_string = hash[length_in_chars+2:length_in_chars+4]

    public_key = hash[length_in_chars +4: ]
    print(public_key)


    sha=SHA256.new(data=public_key.encode('utf-8')).digest()
    r=RIPEMD160.new()
    r.update(sha)
    r=r.hexdigest()

    #ripemd160_hash = hashlib.new('ripemd160', hashlib.sha256(public_key.encode()).digest())
    print(r)

    version=b'\00' # ??????????????????????????????????????????????????????????????????????????????????????????????????
    extended_public_key= version+ bytes.fromhex(r)
    print(extended_public_key)


    sha1 = SHA256.new(data=public_key.encode('utf-8'))
    sha2 = SHA256.new(data=sha1.digest())
    print(sha2)

    checksum=sha2.digest()[0:8]
    print(checksum)


    addr_in_hex=extended_public_key+checksum
    print(addr_in_hex)
    #encode258
    address = base58.b58encode(bytes.fromhex(addr_in_hex)).decode('utf-8')    
    return address

hash="473044022100edf664ebfc12a3998d242fbdd8a1a44c13e4e7f6d7dbddde9ae5610bfd2c9c38021f74ec1e2eca7310baa17c60cbaaffa0503cee680f13fd9a10fd04f2910958c9012103486669962008e0713660b6d69117a65fcecd221d06c1e5077b4d9cd477c0cf98"
addr=get_address(hash)
print("bitcoin addr:", addr)