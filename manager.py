from client import Client
import random
import numpy as np
from util import reconstruct,prg_pad

class Manager:
    def __init__(self, num_parties, num_neighbors, threshold, dropout_rate, vector_len):
        self.num_parties = num_parties
        self.num_neighbors=  num_neighbors
        self.threshold = threshold
        self.prime = 0x7e00001
        self.dropout_rate = dropout_rate
        self.vector_len = vector_len
        # self.server_time = 0
        self.generate_clients()
        self.advertise_key()
        # self.permute = list(range(1,1+num_parties))
        # random.shuffle(self.permute)

    def generate_clients(self):
        self.clients = [Client(i+1,self.threshold) for i in range(self.num_parties)]
        for client in self.clients:
            neighbors = [i for i in range(1,1+self.num_parties) if 
            (i-client.id+self.num_parties)%self.num_parties <= self.num_neighbors/2 or
            (i-client.id+self.num_parties)%self.num_parties >= self.num_parties-self.num_neighbors/2]
            # print(len(neighbors))
            client.assign_neighbors(neighbors)# if i!=client.id])

    def advertise_key(self):
        for client in self.clients:
            client.share()
            local_seed_share = client.messages["local_seed_share"]
            secret_key_share = client.messages["secret_key_share"]
            for j in client.neighbors:
                # print("id test",self.clients[j-1].id, j)
                self.clients[j-1].received["local_seed_share"][client.id] = local_seed_share[j]
                self.clients[j-1].received["secret_key_share"][client.id] = secret_key_share[j]
                self.clients[j-1].received["public_key"][client.id] = client.public_key

    
    def __mask_reconstruct(self, survived):
        recon_mask = 0
        for client in self.clients:
            if client.id in survived:
                shares = {k:self.clients[k-1].received['local_seed_share'][client.id] for k in survived if k in client.neighbors}
                local_seed = reconstruct(shares, self.threshold, self.prime)
                # print(local_seed, client.local_seed)
                # np.random.seed(local_seed)
                prg = prg_pad(local_seed)
                data = b'secrsecr'*self.vector_len
                recon_mask += np.frombuffer(prg.encrypt(data),dtype='int') #np.random.randint(0,self.prime,size=self.vector_len)
            else: #party has dropped
                shares = {k:self.clients[k-1].received["secret_key_share"][client.id] for k in survived if k in client.neighbors}
                secret_key = reconstruct(shares, self.threshold, self.prime)
                for j in client.neighbors:
                    if j not in survived: continue
                    seed_ij = pow(self.clients[j-1].public_key,int(secret_key),self.prime)
                    # np.random.seed(seed_ij)
                    prg=prg_pad(seed_ij)
                    data = b'secrsecr'*self.vector_len
                    
                    if j > client.id:
                        recon_mask += np.frombuffer(prg.encrypt(data),dtype='int')
                    elif j < client.id:
                        recon_mask -= np.frombuffer(prg.encrypt(data),dtype='int')
                    
        return recon_mask

    def secure_aggregation(self):
        x = np.ones(self.vector_len, dtype="int")
        masks = []
        gathered = 0
        
        # dropout
        survived = random.sample(list(range(1,1+self.num_parties)),k=int((1-self.dropout_rate)*self.num_parties))
        
        # mask gathering
        for client in self.clients:#self.clients:
            masks.append(client.mask(x))
            if client.id in survived:
                gathered += masks[-1]
        print(len(survived), "clients survived")
        # print(gathered-10*x)
        gathered -= self.__mask_reconstruct(survived)
        print(gathered[:5])
    
if __name__ == "__main__":
    manager = Manager(1000,160,80,0.25,44436)
    import time
    t = time.time()
    manager.secure_aggregation()
    print(time.time()-t)