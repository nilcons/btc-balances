#!/usr/bin/env python3

# Copyright (c) 2023 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# Original:
#   https://raw.githubusercontent.com/bitcoin/bitcoin/5848a51682181b90035729278310f283a14b9d57/contrib/utxo-tools/utxo_to_sqlite.py
#   https://github.com/bitcoin/bitcoin/pull/27432

# Modifictions by @errge:
#  - SQL format to emphasize btc balances, not individual UTXOs
#  - only store bc1 addresses (and some custom addrs) (for size improvement)
#  - store highest block in metadata
#  - work as a pipe with stdout, stdin

# Algorithm design constraints:
#  - 90% of addresses have a single UTXO
#  - the utxo dump is coming from btc core as a stream
#  - writing to sqlite while we have index is slow (index has to be create post big data dump)
#  - we want to keep the final output sqlite table as small as possible

# Algorithm:
#  - iterate and collect all balances in memory (merging utxos on the way)
#  - dump data to sqlite (without index)
#  - create the index (trick: we just index on last byte of script, and then query has to look like this:)
#    SELECT sats FROM balances WHERE SUBSTR(HEX(scriptpubkey),-2) = '52' AND hex(scriptpubkey) = '0014...52';

# Ideas for later:
#  - 90% of the addresses are single UTXO, can we somehow speculatively already write+index into the sqlite early???
#    - in memory collection is 1.5 minutes, and write is 1 minute, so parallelizing these would be an improvement
#    - otoh, for the first minute bitcoind just doesn't start the dump at all, so the win is limited

import os
import sqlite3
import sys
import time

from collections import defaultdict

def monitor_script(script):
    # By default we only monitor bc1 single-sign addresses (script starts with 0014)
    if script.startswith(b'\x00\x14'): return True

    # Monitoring of additional stuff can still be implemented in a privacy preserving way...
    return script.endswith(b'\xf8\x88\xac')


UTXO_DUMP_MAGIC = b'utxo\xff'
UTXO_DUMP_VERSION = 2
NET_MAGIC_BYTES = {
    b"\xf9\xbe\xb4\xd9": "Mainnet",
    b"\x0a\x03\xcf\x40": "Signet",
    b"\x0b\x11\x09\x07": "Testnet3",
    b"\x1c\x16\x3f\x28": "Testnet4",
    b"\xfa\xbf\xb5\xda": "Regtest",
}


def read_varint(f):
    """Equivalent of `ReadVarInt()` (see serialization module)."""
    n = 0
    while True:
        dat = f.read(1)[0]
        n = (n << 7) | (dat & 0x7f)
        if (dat & 0x80) > 0:
            n += 1
        else:
            return n


def read_compactsize(f):
    """Equivalent of `ReadCompactSize()` (see serialization module)."""
    n = f.read(1)[0]
    if n == 253:
        n = int.from_bytes(f.read(2), "little")
    elif n == 254:
        n = int.from_bytes(f.read(4), "little")
    elif n == 255:
        n = int.from_bytes(f.read(8), "little")
    return n


def decompress_amount(x):
    """Equivalent of `DecompressAmount()` (see compressor module)."""
    if x == 0:
        return 0
    x -= 1
    e = x % 10
    x //= 10
    n = 0
    if e < 9:
        d = (x % 9) + 1
        x //= 9
        n = x * 10 + d
    else:
        n = x + 1
    while e > 0:
        n *= 10
        e -= 1
    return n


def decompress_script(f):
    """Equivalent of `DecompressScript()` (see compressor module)."""
    size = read_varint(f)  # sizes 0-5 encode compressed script types
    if size == 0:  # P2PKH
        return bytes([0x76, 0xa9, 20]) + f.read(20) + bytes([0x88, 0xac])
    elif size == 1:  # P2SH
        return bytes([0xa9, 20]) + f.read(20) + bytes([0x87])
    elif size in (2, 3):  # P2PK (compressed)
        return bytes([33, size]) + f.read(32) + bytes([0xac])
    elif size in (4, 5):  # P2PK (uncompressed)
        compressed_pubkey = bytes([size - 2]) + f.read(32)
        return bytes([65]) + decompress_pubkey(compressed_pubkey) + bytes([0xac])
    else:  # others (bare multisig, segwit etc.)
        size -= 6
        assert size <= 10000, f"too long script with size {size}"
        return f.read(size)


def decompress_pubkey(compressed_pubkey):
    """Decompress pubkey by calculating y = sqrt(x^3 + 7) % p
       (see functions `secp256k1_eckey_pubkey_parse` and `secp256k1_ge_set_xo_var`).
    """
    P = 2**256 - 2**32 - 977  # secp256k1 field size
    assert len(compressed_pubkey) == 33 and compressed_pubkey[0] in (2, 3)
    x = int.from_bytes(compressed_pubkey[1:], 'big')
    rhs = (x**3 + 7) % P
    y = pow(rhs, (P + 1)//4, P)  # get sqrt using Tonelli-Shanks algorithm (for p % 4 = 3)
    assert pow(y, 2, P) == rhs, f"pubkey is not on curve ({compressed_pubkey.hex()})"
    tag_is_odd = compressed_pubkey[0] == 3
    y_is_odd = (y & 1) == 1
    if tag_is_odd != y_is_odd:  # fix parity (even/odd) if necessary
        y = P - y
    return bytes([4]) + x.to_bytes(32, 'big') + y.to_bytes(32, 'big')


def log(s):
    print(s, file = sys.stderr)


def main():
    start_time = time.time()
    # read metadata (magic bytes, version, network magic, block height, block hash, UTXO count)
    f = open("/dev/stdin", 'rb')
    magic_bytes = f.read(5)
    version = int.from_bytes(f.read(2), 'little')
    network_magic = f.read(4)
    block_hash = f.read(32)
    num_utxos = int.from_bytes(f.read(8), 'little')
    if magic_bytes != UTXO_DUMP_MAGIC:
        log(f"Error: provided input file is not an UTXO dump.")
        sys.exit(1)
    if version != UTXO_DUMP_VERSION:
        log(f"Error: provided input file has unknown UTXO dump version {version} "
            f"(only version {UTXO_DUMP_VERSION} supported)")
        sys.exit(1)
    network_string = NET_MAGIC_BYTES.get(network_magic, f"unknown network ({network_magic.hex()})")
    elapsed = time.time() - start_time
    log(f"UTXO Snapshot for {network_string} at block hash "
        f"{block_hash[::-1].hex()[:32]}..., contains {num_utxos} coins, {elapsed:.3f}s")

    utxo_sats = defaultdict(lambda: 0)
    coins_per_hash_left = 0
    prevout_hash = None
    max_height = 0

    for coin_idx in range(1, num_utxos+1):
        # read key (COutPoint)
        if coins_per_hash_left == 0:  # read next prevout hash
            prevout_hash = f.read(32)[::-1].hex()
            coins_per_hash_left = read_compactsize(f)
        prevout_index = read_compactsize(f)
        # read value (Coin)
        code = read_varint(f)
        height = code >> 1
        is_coinbase = code & 1
        amount = decompress_amount(read_varint(f))
        scriptpubkey = decompress_script(f)
        if monitor_script(scriptpubkey):
            utxo_sats[scriptpubkey] += amount
        if height > max_height:
            max_height = height
        coins_per_hash_left -= 1

        if coin_idx % (4096*1024) == 0 or coin_idx == num_utxos:
            elapsed = time.time() - start_time
            log(f"{coin_idx} coins converted [{coin_idx/num_utxos*100:.2f}%], {elapsed:.3f}s")

    elapsed = time.time() - start_time
    log(f"WRITE DATA {elapsed:.3f}s")
    con = sqlite3.connect("/dev/stdout")
    con.execute("CREATE TABLE balances(scriptpubkey BLOB, sats INT)")
    con.executemany("INSERT INTO balances VALUES (?, ?)", utxo_sats.items())
    con.commit()
    elapsed = time.time() - start_time
    log(f"WRITE IDX  {elapsed:.3f}s")
    con.execute("CREATE INDEX idx ON balances(substr(hex(scriptpubkey), -2))")
    con.commit()
    elapsed = time.time() - start_time
    log(f"ALL  DONE  {elapsed:.3f}s, writing metadata")
    con.execute("CREATE TABLE meta(start_time INT, dumpversion INT, network TEXT, utxos INT, blockhash TEXT, height INT)")
    con.execute("INSERT INTO meta VALUES (?, ?, ?, ?, ?, ?)", (start_time, version, network_string, num_utxos, block_hash[::-1].hex(), max_height))
    con.commit()
    con.close()

    if f.read(1) != b'':
        log(f"WARNING: input has not reached EOF yet!")
        sys.exit(1)


if __name__ == '__main__':
    main()
