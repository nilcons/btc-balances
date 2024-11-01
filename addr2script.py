#!venv/bin/python3

from pycoin.symbols.btc import network
import sys

def get_script(addr):
    script = network.parse.address(addr).script()
    return script.hex()

print(get_script(sys.argv[1]))
