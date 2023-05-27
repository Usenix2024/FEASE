'''
:Date:            4/2023
'''
import re, random
from charm.toolbox.pairinggroup import PairingGroup, G1, G2, GT
from charm.toolbox.secretutil import SecretUtil
from charm.toolbox.policytree import PolicyParser

from ac17kp import AC17KPABE
from fabeo22kp import FABEO22KPABE
from FEASE import PEKS_DL
from FEASE_PAEKS import PAEKS_DL
from FEASE_KPABE import Anonymous_KP_ABE
from cwdwl17 import KPabe_search
from mznlhs17 import MZNLHS17


def run_peks(peks, kw_list, kw_policy):
    (pk, sk) = peks.setup()
    trapdoor = peks.trapdoor(pk, sk, kw_policy)
    ct = peks.encrypt(pk, kw_list)
    subsets, result = peks.search(ct, trapdoor)
    
    if debug:
        if result == 1:
            print("Successful search for {}!".format(peks.name))
        else:
            print("Search failed for {}!".format(peks.name))   
    return subsets, result
    
def run_paeks(paeks, kw_list, kw_policy):
    pp = paeks.setup()
    (pk_r, sk_r) = paeks.keygen_r(pp)
    (pk_s, sk_s) = paeks.keygen_s(pp)
    trapdoor = paeks.trapdoor(pp, pk_s, sk_r, kw_policy)
    ct = paeks.encrypt(pk_r, sk_s, kw_list)
    subsets, result = paeks.search(ct, trapdoor)
    
    if debug:
        if result == 1:
            print("Successful search for {}!".format(paeks.name))
        else:
            print("Search failed for {}!".format(paeks.name))   
    return subsets, result 
    
def run_dpeks(peks, kw_list, kw_policy):
    (pk, msk) = peks.setup()
    (pk_s, sk_s) = peks.skeygen(pk)
    ct = peks.encrypt(pk, kw_list)
    trapdoor = peks.trapdoor(msk, pk, pk_s, kw_policy)    
    subsets, result = peks.search(pk, trapdoor, ct, sk_s)
   
    if debug:
        if result == 1:
            print("Successful search for {}!".format(peks.name))
        else:
            print("Search failed for {}!".format(peks.name))   
    return subsets, result       
  
def run_kpabe(kp_abe, attr_list, attr_policy, msg):
    (pk, msk) = kp_abe.setup()
    key = kp_abe.keygen(pk, msk, attr_policy)
    ct = kp_abe.encrypt(pk, msg, attr_list)
    subsets, result = kp_abe.decrypt(pk, ct, key, msg)
    
    if debug:
        if result == 1:
            print("Successful decryption for {}!".format(kp_abe.name))
        else:
            print("Decryption failed for {}!".format(kp_abe.name))   
    return subsets, result
'''
def create_list_and_policy(n_1, n_2):     
    kw_list = ['1001:1']   
    for i in range(2, n_1 + 1):
        kw_list.append(str(1000 + i) + ':' + str(i))        
        
    attr_list = ['1']   
    for i in range(2, n_1 + 1):
        attr_list.append(str(i))      
        
    kw_policy = '1001:1'  
    attr_policy = '1'          
    for i in range(2, n_2 + 1):    
        choice = [' and ', ' or ']
        k = random.choice(choice)      
        kw_policy += k + str(1000 + i) + ':' + str(i)
        attr_policy += k + str(i)
        
    return kw_list, kw_policy, attr_list, attr_policy 
'''    
def wordList_prep(num_words):
    f = open('./words.txt','r')
    lines = f.readlines()
    
    word_list = []
    i = 0
    indices = random.sample(range(1, 466466), num_words)
    for i in indices:
        word = lines[i]
        word = word.split('\n')[0]
        word = word.replace("'", "")
        word = word.replace("-", "")
        word_list.append(word.upper())
    f.close()
    return word_list
    
def create_list_and_policy(n_1, n_2):
    
    word_list = wordList_prep(n_1)
    
    kw_list, attr_list = [], []
    for i in word_list:
        kw = i
        attr = i
        kw = kw + ':' + str(random.choice(range(1, 10)))
        kw_list.append(kw)
        attr_list.append(attr)

    choice = [' and ', ' or ']
    indices = random.sample(range(len(word_list)), n_2)
     
    kw_policy, attr_policy = '', '' 
    for i, num in enumerate(indices):
        policy_name = word_list[num]        
        k = random.choice(choice)    
        
        if i in range(len(indices) - 1):  
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 10))) + '' + k + ''
            attr_policy = attr_policy + policy_name + k + ''
        else:       
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 10)))
            attr_policy = attr_policy + policy_name

    return kw_list, kw_policy, attr_list, attr_policy  
             
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
       
    # choose a random message
    msg = pairing_group.random(GT)  
           
    list_size = 10
    policy_size = 5

    kw_list, kw_policy, attr_list, attr_policy = create_list_and_policy(list_size, policy_size)
    
    #kw_list = ['1001:1', '1002:2', '1003:3', '1004:4', '1005:5', '1006:6', '1007:7', '1008:8', '1009:9', '1010:10']   
    #kw_policy = '(1001:1 and 1002:2) or (1003:3 and 1004:4)'   
    #attr_list = ['1001:1', '1002:2', '1003:3', '1004:4']   
    #attr_policy = '(1001:1 and 1002:2) or (1003:3 and 1004:4)' 
    
    attrs_upper = []
    for i in attr_list:
        attrs_upper.append(i.upper())

    peks = PEKS_DL(pairing_group)
    subsets_1, result_1 = run_peks(peks, kw_list, kw_policy)
    
    paeks = PAEKS_DL(pairing_group)
    subsets_2, result_2 = run_paeks(paeks, kw_list, kw_policy)
    
    dpeks_1 = KPabe_search(pairing_group)
    subsets_3, result_3 = run_dpeks(dpeks_1, kw_list, kw_policy)    
    
    dpeks_2 = MZNLHS17(pairing_group)
    subsets_4, result_4= run_dpeks(dpeks_2, kw_list, kw_policy)     
    
    kp_abe_1 = Anonymous_KP_ABE(pairing_group)
    subsets_5, result_5 = run_kpabe(kp_abe_1, kw_list, kw_policy, msg)  
            
    #ac17_kp = AC17KPABE(pairing_group, 2)
    #subsets_6, result_6 = run_kpabe(ac17_kp, attr_list, attr_policy, msg)  
    
    #fabeo22_kp = FABEO22KPABE(pairing_group)
    #subsets_7, result_7 = run_kpabe(fabeo22_kp, attr_list, attr_policy, msg)  
    
    print(subsets_1, result_1)
    print(subsets_2, result_2)
    print(subsets_3, result_3) 
    print(subsets_4, result_4)     
    print(subsets_5, result_5)
    #print(subsets_6, result_6)
    #print(subsets_7, result_7)
    
if __name__ == "__main__":
    debug = True
    main()
