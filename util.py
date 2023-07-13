import numpy as np
import torch
from collections import OrderedDict
from functools import reduce
from random import SystemRandom
# from galois import GF, Poly
import os
from Cryptodome.Cipher import AES

# os.environ['KMP_DUPLICATE_LIB_OK']='True'

def shamir_share(value, list_to_share, threshold, mod):
    # value: value to shamir sharing
    # list_to_share: list of the id that we want to share our secret with
    # threshold: the number of parties that can together reconstruct the secret
    # mod: modulo that we do shamir sharing in
    # return values: a dictionary with key = list_to_share and value = share
    cryptogen = SystemRandom()
    poly_coeffs = [cryptogen.randrange(mod) for _ in range(threshold-1)]
    shares = []
    for x in list_to_share:
        share = value
        for i,coeff in enumerate(poly_coeffs):
            share = np.mod(share+np.mod(coeff*pow(x,i+1,mod),mod),mod)
        shares.append(share)
    return {k:v for (k,v) in zip(list_to_share,shares)}


def get_lagrange_coeff(list_id, value, mod):
    outputs = []
    # print("listid:",list_id)
    for idx in list_id:
        res = [np.mod((value-j)*pow(idx-j,-1,mod),mod) for j in list_id if j!=idx]
        # print(res)
        coeff = reduce(lambda x,y: np.mod(x*y,mod),res)
        assert coeff != 0
        outputs.append(np.mod(coeff,mod))
    return outputs

def reconstruct(shares, threshold, mod):#, coeffs=None):
    # function to reconstruct the shamir share
    # shares: dictionary consist of party id as keys and polynomial as value
    ids = list(shares.keys())[:threshold]
    values = list(shares.values())[:threshold]
    coeffs = get_lagrange_coeff(ids,0,mod)
    # print(shares, coeffs)
    
    output = np.mod(np.dot(coeffs,values),mod)
    return np.mod(output,mod)

def prg_pad(seed):
    pseed=(int(seed)&(1<<128)-1).to_bytes(16,'big')
    prg = AES.new(pseed,AES.MODE_CBC,iv=b'0123456789abcdef')
    return prg

if __name__=="__main__":
    print("TEST")
    import time
    value = 30
    prime = 0x7e00001
    threshold = 3
    t = time.time()
    shares = shamir_share(value,[1,2,3,4,5,6,7,8,9,10],threshold,prime)
    # shares = shamir_share(value, [1,2,3], 2, prime, galois_field)
    print(time.time()-t)
    # print(shares)
    # print(get_lagrange_coeff([1,3],0,prime))
    print(reconstruct(shares,threshold,prime))
