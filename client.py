# from Cryptodome
from random import SystemRandom
from util import *

class Client:
    def __init__(self, id, threshold):
        self.id = id
        self.threshold = threshold
        self.g = 0x5
        self.prime = 0x7e00001
        self.cryptogen = SystemRandom()
        secret = [self.cryptogen.randrange(2,self.prime-1) for _ in range(2)]
        self.local_seed = secret[0]
        self.secret_key = secret[1]
        self.public_key = pow(self.g,self.secret_key,self.prime)
        self.messages = dict()
        self.received = {"local_seed_share":dict(),"secret_key_share":dict(),"public_key":dict()}

    def assign_neighbors(self, neighbors):
        self.neighbors = neighbors

    def share(self):
        local_seed_share = shamir_share(self.local_seed, self.neighbors, self.threshold, self.prime)
        secret_key_share = shamir_share(self.secret_key, self.neighbors, self.threshold, self.prime)
        self.messages["local_seed_share"] = local_seed_share
        self.messages["secret_key_share"] = secret_key_share
        
    def mask(self,x):
        # np.random.seed(self.local_seed)
        prg = prg_pad(self.local_seed)
        data = b'secrsecr'*len(x)
        mask=0
        mask += np.frombuffer(prg.encrypt(data),dtype='int')#np.random.randint(0,self.prime,len(x))
        for j in self.neighbors:
            if j==self.id:continue
            seed_ij = pow(self.received["public_key"][j],self.secret_key,self.prime)
            # print(self.id, j, seed_ij)
            # np.random.seed(seed_ij)
            prg = prg_pad(seed_ij)
            
            # print
            if j > self.id:
                mask -= np.frombuffer(prg.encrypt(data),dtype='int')
            elif j < self.id:
                mask += np.frombuffer(prg.encrypt(data),dtype='int')
        # print(mask)
        return x + mask