'''
Ru Meng, Yanwei Zhou, Jianting Ning, Kaitai Liang, Jinguang Han, Willy Susilo
 
| From: "An Efficient Key-Policy Attribute-Based Searchable Encryption in Prime-Order Groups"
| Published in: International Conference on Provable Security (ProvSec) 2017
| type:           KP-ABE based PEKS
| setting:        Type-III pairing

:Authors:    
:Date:       27/04/2023
'''
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.ABEnc import ABEnc
#from charm.toolbox.hash_module import Waters, Hash
from msp import MSP
from policytree import PolicyParser
from secretutil import SecretUtil
import copy

debug = False
class MZNLHS17(ABEnc):
    
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "Ru Meng PEKS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(group_obj)        

    def setup(self):
        g, g_hat = self.group.random(G1), self.group.random(G2)                    
        x1, x2, x3 = self.group.random(), self.group.random(), self.group.random()
        u = g ** x1
        u_hat = g_hat ** x1
        h = g ** x2
        h_hat = g_hat ** x2
        delta = g ** x3
        delta_hat = g_hat ** x3
        alpha, d1, d2, d3, d4 = self.group.random(), self.group.random(), self.group.random(), self.group.random(), self.group.random()
        g1 = g**d1
        g2 = g**d2
        g3 = g**d3
        g4 = g**d4
        pk = {"g":g, "u":u, "h":h, "delta":delta, "g1":g1, "g2":g2, "g3":g3, "g4":g4, "Omega":pair(g, g_hat)**alpha}
        msk = pk.copy()
        msk["alpha"] = alpha
        msk["g_hat"] = g_hat
        msk["u_hat"] = u_hat
        msk["h_hat"] = h_hat
        msk["delta_hat"] = delta_hat
        msk["d1"] = d1
        msk["d2"] = d2
        msk["d3"] = d3
        msk["d4"] = d4

        return (pk, msk)

    def skeygen(self, pk):
        kappa = self.group.random()
        (pk_s, sk_s) = (pk["g"] ** kappa, kappa)
        return (pk_s, sk_s)

    def encrypt(self, pk, kw_list):
        mu, s, s1, s2 = self.group.random(), self.group.random(), self.group.random(), self.group.random()
        
        C = pk["Omega"]**mu
        C1 = pk["g"]**mu
        C2 = ( pk["h"]  )
        
        kw_list_name = []
        for kw in kw_list:
            name = kw.split(':')[0] 
            kw_list_name.append(name)            
        
        for kw in kw_list:           
            C2 *= (pk["u"] ** self.group.hash(kw, ZR))
                   
        C2 = C2 ** s
        C2 *= pk["delta"] ** -mu
        E1 = pk["g1"] ** (s - s1)
        E2 = pk["g2"] ** s1
        E3 = pk["g3"] ** (s - s2)
        E4 = pk["g4"] ** s2        
        
        return {"kw_set_name": kw_list_name, "C":C, "C1":C1, "C2":C2, "E1":E1, "E2":E2, "E3":E3, "E4":E4, "mu":mu}
    
    def trapdoor(self, msk, pk, pk_s, kw_policy):
    
        kw_policy = util.createPolicy(kw_policy)   # convert the policy from string to Bin.node format
        kw_policy_name = copy.deepcopy(kw_policy)
    
        parser = PolicyParser()
        parser.policy_strip(kw_policy_name) # remove keyword values in the policy 
        
        mono_span_prog = self.util.convert_policy_to_msp(kw_policy)
        num_cols = self.util.len_longest_row    
        
        # pick random shares
        v = [msk['alpha']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)            

        trapdoor = dict()
        r, r_prime = self.group.random(), self.group.random()

        D = msk["g"] ** r
        D_hat = msk["g_hat"] ** r_prime
        trapdoor["D"] = D
        trapdoor["D_hat"] = D_hat

        X = pair(pk_s, D_hat) ** r
        
        X = self.group.hash(str(X), ZR)             
                           
        for kw, row in mono_span_prog.items():        
            kw_stripped = self.util.strip_index(kw)
            name = kw_stripped.split(':')[0]  
            len_row = len(row)
            lamb = sum(i[0] * i[1] for i in zip(row, v[:len_row]))         
        
            t1, t2 = self.group.random(), self.group.random()
            d1 = msk["d1"]
            d2 = msk["d2"]
            d3 = msk["d3"]
            d4 = msk["d4"]

            t = d1*d2*t1 + d3*d4*t2
            h = self.group.hash(kw_stripped, ZR)          
            Y = (msk["u_hat"]**h) * msk["h_hat"]

            D = ( msk["g_hat"] ** lamb ) * ( msk["delta_hat"] **  t)
            R = msk["g_hat"]** (t+X)
            T1 = Y ** (-d2*t1)
            T2 = Y ** (-d1*t1)
            T3 = Y ** (-d4*t2)
            T4 = Y ** (-d3*t2)
            
            Q = dict()
            tmp = mono_span_prog.copy()
            del tmp[kw]
            
            for Q_kw in tmp.keys():
                Q_name_value = self.util.strip_index(Q_kw)
                Q_name = Q_name_value.split(':')[0]  
                hQ = self.group.hash(Q_name_value, ZR)
                Q_tmp = msk["u_hat"] ** (-hQ)
                Q[Q_name] = {"Q1":Q_tmp ** (d2*t1), "Q2":Q_tmp ** (d1*t1), "Q3":Q_tmp ** (d4*t2), "Q4":Q_tmp ** (d3*t2)}

            trapdoor[name] = {"D":D, "R":R, "T1":T1, "T2":T2, "T3":T3, "T4":T4 ,"Q":Q}
            trapdoor["g_hat"] = msk["g_hat"]
        trapdoor["kw_policy_name"] = kw_policy_name
        return trapdoor
    def search(self, pk, trapdoor, ct, sk_s):     
        subsets = util.prune(trapdoor['kw_policy_name'], ct['kw_set_name'], 1)
        
        if subsets == False:  
            print('Keyword names are not matching.')
            result = 0
            return subsets, result

        T1 = T2 = T3 = T4 = D = R = 1
        
        X = pair(trapdoor["D"], trapdoor["D_hat"]) ** sk_s
        X = self.group.hash(str(X), ZR)
        X = trapdoor["g_hat"] ** X
        
        for one_subset in subsets:
            for one_name in one_subset:
                name = one_name.getAttribute()      
                tmp1 = trapdoor[name]["T1"]               
                tmp2 = trapdoor[name]["T2"]
                tmp3 = trapdoor[name]["T3"]
                tmp4 = trapdoor[name]["T4"]

                T = one_subset.copy()
                T.remove(name)
                for item in T:
                    item = item.getAttribute()
                    tmp1 *= trapdoor[name]["Q"][item]["Q1"]
                    tmp2 *= trapdoor[name]["Q"][item]["Q2"]
                    tmp3 *= trapdoor[name]["Q"][item]["Q3"]
                    tmp4 *= trapdoor[name]["Q"][item]["Q4"]

                T1 *= tmp1
                T2 *= tmp2
                T3 *= tmp3
                T4 *= tmp4
                D *= trapdoor[name]["D"]
                R *= (trapdoor[name]["R"] / X)                
        
            Y = pair(ct["C1"], D) * pair(ct["C2"], R) * pair(ct["E1"], T1) * pair(ct["E2"], T2) * pair(ct["E3"], T3) * pair(ct["E4"], T4)
            if  Y == (pk["Omega"] ** ct["mu"]):
                result = 1
                break
            else: 
                result = 0
                continue    
        return subsets, result
        
