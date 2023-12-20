from cryptotools.BTC import Transaction

def hex_decode(hex):
    tx = Transaction.from_hex(hex)
    return tx.json()
