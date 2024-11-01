#!venv/bin/python3

from pycoin.symbols.btc import network
import sys

def get_addr(script):
    return network.address.for_script(bytes.fromhex(script))

print(get_addr(sys.argv[1]))
