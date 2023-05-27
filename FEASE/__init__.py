'''

| From: "FEASE: Fast and Expressive Asymmetric Searchable Encryption"
| Notes: Implemented the scheme in Figure 2 
| type:           Expressive PEKS scheme
| setting:        Type-III Pairing

:Authors:         
:Date:            27/04/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, ZR, G1, G2, GT, pair
from charm.toolbox.ABEnc import ABEnc
from msp import MSP
from policytree import PolicyParser
from secretutil import SecretUtil
import time

import re, numpy, copy

debug = False

class PEKS_DL(ABEnc):         
    def __init__(self, group_obj, verbose=False):
        ABEnc.__init__(self)
        self.name = "PEKS"
        self.group = group_obj
        self.util = MSP(self.group, verbose)
        global util
        util = SecretUtil(self.group)          

    def setup(self):
        #if debug:
        #    print('\nSetup algorithm:\n')

        # pick parameters
        g_1 = self.group.random(G1)
        g_2 = self.group.random(G2)       
        
        a = self.group.random(ZR)
        b_1 = self.group.random(ZR)
        b_2 = self.group.random(ZR)
        e_g1g2 = pair(g_1, g_2)
        
        # public key and secret key
        pk = {'g_1': g_1, 'g_2': g_2, 'g_2^b_1': g_2 ** b_1, 'g_2^b_2': g_2 ** b_2, 'e_g1g2_a': e_g1g2 ** a}
        sk = {'a': a, 'b_1': b_1, 'b_2': b_2}
       
        return pk, sk

    def encrypt(self, pk, kw_list):
        #if debug:
        #    print('\nEncryption algorithm:\n')

        s_1 = self.group.random(ZR)
        s_2 = self.group.random(ZR)
        s = s_1 + s_2
        
        kw_list_name = []
        for kw in kw_list:
            name = kw.split(':')[0] 
            kw_list_name.append(name)     

        ct_1 = {}
        for kw in kw_list:
            x = kw_list.index(kw)
            kwHash = self.group.hash(kw, G1)
            ct_1[kw_list_name[x]] = kwHash ** s
        
        ct_2 = pk['g_2^b_1'] ** s_1
        ct_3 = pk['g_2^b_2'] ** s_2
        ct_4 = pk['e_g1g2_a'] ** s
        
        return {'kw_set_name': kw_list_name, 'ct_1': ct_1, 'ct_2': ct_2, 'ct_3': ct_3, 'ct_4': ct_4}

    def trapdoor(self, pk, sk, kw_policy):
        #if debug:
        #    print('\nTrapdoor generation algorithm:\n')

        kw_policy = util.createPolicy(kw_policy)   # convert the policy from string to Bin.node format
        kw_policy_name = copy.deepcopy(kw_policy)
    
        parser = PolicyParser()
        parser.policy_strip(kw_policy_name) # remove keyword values in the policy 

        mono_span_prog = self.util.convert_policy_to_msp(kw_policy)
        num_cols = self.util.len_longest_row
        
        # pick randomness
        r = self.group.random(ZR)
        
        # pick random shares
        v = [sk['a']]
        for i in range(num_cols-1):
            rand = self.group.random(ZR)
            v.append(rand)
        
        tok_1 = pk['g_2'] ** r
	
        tok_2 = {}
        tok_3 = {}
        
        skt_1 = 1/sk['b_1']
        skt_2 = 1/sk['b_2']
        
        # Using MSP
        for kw, row in mono_span_prog.items():
            kw_stripped = self.util.strip_index(kw)
            kw_name_label = kw_stripped.split(':')[0]
            kwHash = self.group.hash(kw_stripped, G1)
            len_row = len(row)
            Mivtop = sum(i[0] * i[1] for i in zip(row, v[:len_row]))
            tep = pk['g_1'] ** Mivtop * kwHash ** r
            tok_2[kw_name_label] = tep ** skt_1
            tok_3[kw_name_label] = tep ** skt_2
                        
        return {'kw_policy_name': kw_policy_name, 'tok_1': tok_1, 'tok_2': tok_2, 'tok_3': tok_3} 

    def search(self, ct, trapdoor):

        #if debug:
        #    print('\nDecryption algorithm:\n')

        subsets = util.prune(trapdoor['kw_policy_name'], ct['kw_set_name'], 1)

        if subsets == False:  
            print('Keyword names are not matching.')
            result = 0
            return subsets, result
              
        for one_subset in subsets:
            prod_ct_1 = 1
            prod_tok_2 = 1
            prod_tok_3 = 1

            for one_name in one_subset:
                k = one_name.getAttribute()
                
                for name in ct['ct_1'].keys():
                    if k == name: 
                        prod_ct_1 *= ct['ct_1'][k] #** gamma_set[k]
                        #print('ct_1', k)
                                                                                                                                                
                for name in trapdoor['tok_2'].keys(): 
                    if k == name:
                        prod_tok_2 *= trapdoor['tok_2'][k] #** gamma_set[k]
                        #print('tk_2', k)         
                
                for name in trapdoor['tok_3'].keys():
                    if k == name:
                        prod_tok_3 *= trapdoor['tok_3'][k] #** gamma_set[k]
                        #print('tk_3', k)                      
                    
            e1 = pair(prod_ct_1, trapdoor['tok_1'])
            e2 = pair(prod_tok_2, ct['ct_2'])
            e3 = pair(prod_tok_3, ct['ct_3'])       
            kem = (e2 * e3)/e1             
            if ct['ct_4'] == kem: # Check if the search is successful
                result = 1
                break                    
            else:    
                result = 0                
                continue                                   
        return subsets, result         
              
