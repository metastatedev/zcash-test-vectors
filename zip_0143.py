#!/usr/bin/env python3
from pyblake2 import blake2b
import struct

from transaction import (
    MAX_MONEY,
    OVERWINTER_TX_VERSION,
    Script,
    Transaction,
)
from tv_output import render_args, render_tv, Some
from tv_rand import Rand


SIGHASH_ALL = 1
SIGHASH_NONE = 2
SIGHASH_SINGLE = 3
SIGHASH_ANYONECANPAY = 0x80

NOT_AN_INPUT = -1 # For portability of the test vectors; replaced with None for Rust

def getHashPrevouts(tx):
    digest = blake2b(digest_size=32, person=b'MASP_PrevoutHash')
    for x in tx.vin:
        digest.update(bytes(x.prevout))
    return digest.digest()

def getHashSequence(tx):
    digest = blake2b(digest_size=32, person=b'MASP_SequencHash')
    for x in tx.vin:
        digest.update(struct.pack('<I', x.nSequence))
    return digest.digest()

def getHashOutputs(tx):
    digest = blake2b(digest_size=32, person=b'MASP_OutputsHash')
    for x in tx.vout:
        digest.update(bytes(x))
    return digest.digest()

def getHashJoinSplits(tx):
    digest = blake2b(digest_size=32, person=b'MASP_JSplitsHash')
    for jsdesc in tx.vJoinSplit:
        digest.update(bytes(jsdesc))
    digest.update(tx.joinSplitPubKey)
    return digest.digest()


def signature_hash(scriptCode, tx, nIn, nHashType, amount, consensusBranchId):
    hashPrevouts = b'\x00'*32
    hashSequence = b'\x00'*32
    hashOutputs = b'\x00'*32
    hashJoinSplits = b'\x00'*32

    if not (nHashType & SIGHASH_ANYONECANPAY):
        hashPrevouts = getHashPrevouts(tx)

    if (not (nHashType & SIGHASH_ANYONECANPAY)) and \
        (nHashType & 0x1f) != SIGHASH_SINGLE and \
        (nHashType & 0x1f) != SIGHASH_NONE:
        hashSequence = getHashSequence(tx)

    if (nHashType & 0x1f) != SIGHASH_SINGLE and \
        (nHashType & 0x1f) != SIGHASH_NONE:
        hashOutputs = getHashOutputs(tx)
    elif (nHashType & 0x1f) == SIGHASH_SINGLE and \
        0 <= nIn and nIn < len(tx.vout):
        digest = blake2b(digest_size=32, person=b'MASP_OutputsHash')
        digest.update(bytes(tx.vout[nIn]))
        hashOutputs = digest.digest()

    if len(tx.vJoinSplit) > 0:
        hashJoinSplits = getHashJoinSplits(tx)

    digest = blake2b(
        digest_size=32,
        person=b'MASP_SigHash' + struct.pack('<I', consensusBranchId),
    )

    digest.update(struct.pack('<I', tx.header()))
    digest.update(struct.pack('<I', tx.nVersionGroupId))
    digest.update(hashPrevouts)
    digest.update(hashSequence)
    digest.update(hashOutputs)
    digest.update(hashJoinSplits)
    digest.update(struct.pack('<I', tx.nLockTime))
    digest.update(struct.pack('<I', tx.nExpiryHeight))
    digest.update(struct.pack('<I', nHashType))

    if nIn != NOT_AN_INPUT:
        digest.update(bytes(tx.vin[nIn].prevout))
        digest.update(bytes(scriptCode))
        digest.update(struct.pack('<Q', amount))
        digest.update(struct.pack('<I', tx.vin[nIn].nSequence))

    return digest.digest()


def main():
    args = render_args()

    from random import Random
    rng = Random(0xabad533d)
    def randbytes(l):
        ret = []
        while len(ret) < l:
            ret.append(rng.randrange(0, 256))
        return bytes(ret)
    rand = Rand(randbytes)

    consensusBranchId = 0x5ba81b19 # Overwinter

    test_vectors = []
    for i in range(10):
        tx = Transaction(rand, OVERWINTER_TX_VERSION)
        scriptCode = Script(rand)
        nIn = rand.u8() % (len(tx.vin) + 1)
        if nIn == len(tx.vin):
            nIn = NOT_AN_INPUT
        nHashType = SIGHASH_ALL if nIn == NOT_AN_INPUT else rand.a([
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_ALL | SIGHASH_ANYONECANPAY,
            SIGHASH_NONE | SIGHASH_ANYONECANPAY,
            SIGHASH_SINGLE | SIGHASH_ANYONECANPAY,
        ])
        amount = rand.u64() % (MAX_MONEY + 1)

        sighash = signature_hash(
            scriptCode,
            tx,
            nIn,
            nHashType,
            amount,
            consensusBranchId,
        )

        test_vectors.append({
            'tx': bytes(tx),
            'script_code': scriptCode.raw(),
            'transparent_input': nIn,
            'hash_type': nHashType,
            'amount': amount,
            'consensus_branch_id': consensusBranchId,
            'sighash': sighash,
        })

    render_tv(
        args,
        'zip_0143',
        (
            ('tx', {'rust_type': 'Vec<u8>', 'bitcoin_flavoured': False}),
            ('script_code', 'Vec<u8>'),
            ('transparent_input', {
                'rust_type': 'Option<u32>',
                'rust_fmt': lambda x: None if x == -1 else Some(x),
                }),
            ('hash_type', 'u32'),
            ('amount', 'i64'),
            ('consensus_branch_id', 'u32'),
            ('sighash', '[u8; 32]'),
        ),
        test_vectors,
    )


if __name__ == '__main__':
    main()
