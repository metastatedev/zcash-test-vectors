#!/usr/bin/env python3
import sys; assert sys.version_info[0] >= 3, "Python 3 required."

from pyblake2 import blake2s

from sapling_pedersen import (
    mixing_pedersen_hash,
    windowed_pedersen_commitment,
)
from sapling_utils import i2lebsp

from sapling_generators import VALUE_COMMITMENT_VALUE_BASE

def note_commit(rcm, g_d, pk_d, v, ag):
    return windowed_pedersen_commitment(rcm, [1] * 6 + ag + i2lebsp(64, v) + g_d + pk_d)

def prf_nf_sapling(nk_star, rho_star):
    digest = blake2s(person=b'MASP__nf')
    digest.update(nk_star)
    digest.update(rho_star)
    return digest.digest()

def note_nullifier(nk, cm, pos):
    rho = mixing_pedersen_hash(cm, pos)
    return prf_nf_sapling(bytes(nk), bytes(rho))
