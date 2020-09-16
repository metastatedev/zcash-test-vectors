#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2s

from sapling_jubjub import Point, JUBJUB_COFACTOR
from tv_output import render_args, render_tv
from sapling_utils import i2leosp

# First 64 bytes of the BLAKE2s input during group hash.
# This is chosen to be some random string that we couldn't have
# anticipated when we designed the algorithm, for rigidity purposes.
# We deliberately use an ASCII hex string of 32 bytes here.
URS = b'096b36a5804bfacef1691e173c366a47ff5ba84a44f26ddd7e8d9f79d5b42df0'


#
# Group hash
#

def group_hash(D, M, std = True):
    digest = blake2s(person=D)
    if std: digest.update(URS)
    digest.update(M)
    p = Point.from_bytes(digest.digest())
    if p is None:
        return None
    q = p * JUBJUB_COFACTOR if std else p
    if q == Point.ZERO:
        return None
    return q

def find_group_hash(D, M):
    i = 0
    while True:
        p = group_hash(D, M + bytes([i]))
        if p is not None:
            return p
        i += 1
        assert i < 256


#
# Sapling generators
#
ASSET_ID = b'sO\x0e\xc5os\x1e\x02\xccs~ki=\xb5+\x82\x1fonL\xd7\xfe<vCS\xf2cf\x9f\xbe' # AssetType b'default' under old repeated hashing derivation

SPENDING_KEY_BASE = find_group_hash(b'MASP__G_', b'')
PROVING_KEY_BASE = find_group_hash(b'MASP__H_', b'')
NOTE_POSITION_BASE = find_group_hash(b'MASP__J_', b'')
WINDOWED_PEDERSEN_RANDOMNESS_BASE = find_group_hash(b'MASP__PH', b'r')
VALUE_COMMITMENT_VALUE_BASE = group_hash(b'MASP__v_', ASSET_ID, std=False)
VALUE_COMMITMENT_RANDOMNESS_BASE = find_group_hash(b'MASP__r_', b'r')

required_bases = 4
PEDERSEN_BASES = [find_group_hash(b'MASP__PH', i2leosp(32, iminus1))
                  for iminus1 in range(0, required_bases)]

def main():
    render_tv(
        render_args(),
        'sapling_generators',
        (
            ('skb', '[u8; 32]'),
            ('pkb', '[u8; 32]'),
            ('npb', '[u8; 32]'),
            ('wprb', '[u8; 32]'),
            ('vcvb', '[u8; 32]'),
            ('vcrb', '[u8; 32]'),
            ('pb0', '[u8; 32]'),
            ('pb1', '[u8; 32]'),
            ('pb2', '[u8; 32]'),
            ('pb3', '[u8; 32]'),
        ),
        {
            'skb': bytes(SPENDING_KEY_BASE),
            'pkb': bytes(PROVING_KEY_BASE),
            'npb': bytes(NOTE_POSITION_BASE),
            'wprb': bytes(WINDOWED_PEDERSEN_RANDOMNESS_BASE),
            'vcvb': bytes(VALUE_COMMITMENT_VALUE_BASE),
            'vcrb': bytes(VALUE_COMMITMENT_RANDOMNESS_BASE),
            'pb0': bytes(PEDERSEN_BASES[0]),
            'pb1': bytes(PEDERSEN_BASES[1]),
            'pb2': bytes(PEDERSEN_BASES[2]),
            'pb3': bytes(PEDERSEN_BASES[3]),
        },
    )


if __name__ == '__main__':
    main()
