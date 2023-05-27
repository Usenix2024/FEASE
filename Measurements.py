'''
:Date:            4/2023
'''

from charm.toolbox.pairinggroup import PairingGroup, GT
from policytree import PolicyParser
from secretutil import SecretUtil
from msp import MSP
from ac17kp import AC17KPABE
from fabeo22kp import FABEO22KPABE
from FEASE import PEKS_DL
from FEASE_PAEKS import PAEKS_DL
from FEASE_KPABE import Anonymous_KP_ABE
from cwdwl17 import KPabe_search
from mznlhs17 import MZNLHS17
import re, random, copy
import time


#--------------------------------------------------- Measure average time module ----------------------------------------------
def measure_average_times_peks(peks, kw_list, kw_policy, N=5):   
    sum_setup=0
    sum_enc=0
    sum_trapdoor=0
    sum_search=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, sk) = peks.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # encryption time
        start_enc = time.time()
        ct = peks.encrypt(pk, kw_list)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # trapdoor time
        start_trapdoor = time.time()
        trapdoor = peks.trapdoor(pk, sk, kw_policy)
        end_trapdoor = time.time()
        time_trapdoor = end_trapdoor - start_trapdoor
        sum_trapdoor += time_trapdoor

        # search time
        start_search = time.time()
        subsets, result = peks.search(ct, trapdoor)
        end_search = time.time()
        time_search = end_search - start_search
        sum_search += time_search
        
        return [time_setup, time_trapdoor, time_enc, time_search], subsets

def measure_average_times_paeks(paeks, kw_list, kw_policy, N=5):    
    sum_setup=0
    sum_keygen_r=0
    sum_keygen_s=0
    sum_enc=0
    sum_trapdoor=0
    sum_search=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        pp = paeks.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup
        
        # keyGen_r time
        start_keygen_r = time.time()
        (pk_r, sk_r) = paeks.keygen_r(pp)
        end_keygen_r = time.time()
        time_keygen_r = end_keygen_r - start_keygen_r
        sum_keygen_r += time_keygen_r

        # keyGen_s time
        start_keygen_s = time.time()
        (pk_s, sk_s) = paeks.keygen_s(pp)
        end_keygen_s = time.time()
        time_keygen_s = end_keygen_s - start_keygen_s
        sum_keygen_s += time_keygen_s

        # encryption time
        start_enc = time.time()
        ct = paeks.encrypt(pk_r, sk_s, kw_list)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # Trapdoor time
        start_trapdoor = time.time()
        trapdoor = paeks.trapdoor(pp, pk_s, sk_r, kw_policy)
        end_trapdoor = time.time()
        time_trapdoor = end_trapdoor - start_trapdoor
        sum_trapdoor += time_trapdoor

        # Search time
        start_search = time.time()
        subsets, result = paeks.search(ct, trapdoor)
        end_search  = time.time()
        time_search  = end_search - start_search 
        sum_search  += time_search 
    
    # compute average time
    time_setup = sum_setup/N
    time_keygen_r = sum_keygen_r/N
    time_keygen_s = sum_keygen_s/N
    time_enc = sum_enc/N
    time_trapdoor = sum_trapdoor/N
    time_search = sum_search/N

    return [time_setup, time_keygen_r, time_keygen_s, time_trapdoor, time_enc, time_search], subsets           
        
def measure_average_times_kpabe(abe, kw_list, kw_policy, msg, N=5):   
    sum_setup=0
    sum_enc=0
    sum_keygen=0
    sum_decrypt=0

    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, msk) = abe.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # encryption time
        start_enc = time.time()
        ct = abe.encrypt(pk, msg, kw_list)
        end_enc = time.time()
        time_enc = end_enc - start_enc
        sum_enc += time_enc

        # trapdoor time
        start_keygen = time.time()
        key = abe.keygen(pk, msk, kw_policy)
        end_keygen = time.time()
        time_keygen = end_keygen - start_keygen
        sum_keygen += time_keygen

        # decryption time
        start_decrypt = time.time()
        subsets, result = abe.decrypt(pk, ct, key, msg)
        end_decrypt = time.time()
        time_decrypt = end_decrypt - start_decrypt
        sum_decrypt += time_decrypt       
    
    # compute average time
    time_setup = sum_setup/N
    time_enc = sum_enc/N
    time_keygen = sum_keygen/N
    time_decrypt = sum_decrypt/N

    return [time_setup, time_keygen, time_enc, time_decrypt], subsets 

def measure_average_times_dpeks(peks, kw_list, kw_policy, N=5):   
    sum_setup = 0
    sum_skeygen = 0
    sum_enc = 0
    sum_trapdoor = 0
    sum_dec = 0
   
    for i in range(N):
        # setup time
        start_setup = time.time()
        (pk, msk) = peks.setup()
        end_setup = time.time()
        time_setup = end_setup-start_setup
        sum_setup += time_setup

        # Cloud server keygen time
        start_skeygen = time.time()
        (pk_s, sk_s) = peks.skeygen(pk)
        end_skeygen = time.time()
        time_skeygen = end_skeygen-start_skeygen
        sum_skeygen += time_skeygen

        # encryption time
        start_enc = time.time()
        ct = peks.encrypt(pk, kw_list)
        end_enc = time.time()
        time_enc = end_enc-start_enc
        sum_enc += time_enc

        # keygen time
        start_trapdoor = time.time()
        trapdoor = peks.trapdoor(msk, pk, pk_s, kw_policy)
        end_trapdoor = time.time()
        time_trapdoor = end_trapdoor-start_trapdoor
        sum_trapdoor += time_trapdoor

        # decryption time
        start_dec = time.time()
        subsets, result = peks.search(pk, trapdoor, ct, sk_s)
        end_dec = time.time()
        time_dec = end_dec-start_dec
        sum_dec += time_dec

    # compute average time
    time_setup = sum_setup/N
    time_skeygen = sum_skeygen/N
    time_enc = sum_enc/N
    time_trapdoor = sum_trapdoor/N
    time_dec = sum_dec/N

    return [time_setup, time_skeygen, time_trapdoor, time_enc, time_dec], subsets   


#-------------------------------------------------- print running time module -------------------------------------------------
def print_running_time_peks(scheme_name, times):
    record = '{:<20}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f')
    print(record)
    return record
        
def print_running_time_paeks(scheme_name, times):
    record = '{:<11}'.format(scheme_name) + format(times[0]*1000, '7.2f') + ' '  + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + ' ' + format(times[3]*1000, '7.2f') + ' ' + format(times[4]*1000, '7.2f') + ' ' + format(times[5]*1000, '7.2f')
    print(record)
    return record    
    
def print_running_time_kpabe(scheme_name, times):
    record = '{:<22}'.format(scheme_name) + format(times[0]*1000, '7.2f') + '   ' + format(times[1]*1000, '7.2f') + '  ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f')
    print(record)
    return record
    
def print_running_time_dpeks(scheme_name, times):
    record = '{:<16}'.format(scheme_name) + format(times[0]*1000, '7.2f') + ' '  + format(times[1]*1000, '7.2f') + ' ' + format(times[2]*1000, '7.2f') + '  ' + format(times[3]*1000, '7.2f') + '  ' + format(times[4]*1000, '7.2f')
    print(record)
    return record    


#-------------------------------------------------- run all module ------------------------------------------------------------
def run_peks(pairing_group, kw_policy, kw_list): 

    peks_1 = PEKS_DL(pairing_group)
    peks_1_times, subsets = measure_average_times_peks(peks_1, kw_list, kw_policy)
     
    n1, n2, m, i = get_par(pairing_group, kw_policy, kw_list, subsets)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'TkGen', 'Enc', 'Search']   
    algo_string = 'PEKS {:<15}'.format('') + '  ' + algos[0] + '     ' + algos[1] + '     ' + algos[2] + '     ' + algos[3]    
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record = print_running_time_peks(peks_1.name, peks_1_times)    
    
    print('-'*62)          
   
    with open('Results/PEKS Results.txt', 'a') as f:
        f.write('PEKS: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record + '\n')
        
        f.write('\n')     
    open('Results/PEKS Results.txt', 'r')  
    with open('Results/PEKS Results.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return     
    
def run_paeks(pairing_group, kw_policy, kw_list):
    
    paeks = PAEKS_DL(pairing_group)
    paeks_times, subsets = measure_average_times_paeks(paeks, kw_list, kw_policy)
     
    n1, n2, m, i = get_par(pairing_group, kw_policy, kw_list, subsets)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KGen_r', 'KGen_s', 'TkGen', 'Encrypt', 'Search']
    algo_string = 'PAEKS {:<5}'.format('') + '  ' + algos[0] + '   ' + algos[1] + '   ' + algos[2] + '  ' + algos[3] + '  ' + algos[4] + '  ' + algos[5]  
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record = print_running_time_paeks(paeks.name, paeks_times)    
    
    print('-'*62)          
   
    with open('Results/PAEKS Results.txt', 'a') as f:
        f.write('PAEKS: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record + '\n')
        
        f.write('\n')     
    open('Results/PAEKS Results.txt', 'r')  
    with open('Results/PAEKS Results.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return       
    
    
def run_kpabe(pairing_group, kw_list, kw_policy, attr_list, attr_policy, msg):  
    
    kp_abe_1 = Anonymous_KP_ABE(pairing_group)
    kp_abe_1_times, subsets_1 = measure_average_times_kpabe(kp_abe_1, kw_list, kw_policy, msg)   
    
    ac17_kp = AC17KPABE(pairing_group, 2)
    ac17_kp_times, subsets_3 = measure_average_times_kpabe(ac17_kp, attr_list, attr_policy, msg)    
    
    fabeo22_kp = FABEO22KPABE(pairing_group)
    fabeo22_kp_times, subsets_4 = measure_average_times_kpabe(fabeo22_kp, attr_list, attr_policy, msg)    
     
    n1, n2, m, i = get_par(pairing_group, kw_policy, kw_list, subsets_1)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'KeyGen', 'Enc', 'Dec']   
    algo_string = 'KP-ABE {:<15}'.format('') + '  ' + algos[0] + '    ' + algos[1] + '     ' + algos[2] + '      ' + algos[3]
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_kpabe(kp_abe_1.name, kp_abe_1_times)       
    record_2 = print_running_time_kpabe(ac17_kp.name, ac17_kp_times)
    record_3 = print_running_time_kpabe(fabeo22_kp.name, fabeo22_kp_times)     
         
    print('-'*62)          
   
    with open('Results/KP-ABE Results.txt', 'a') as f:
        f.write('KP-ABE: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n')
        f.write(record_2 + '\n')
        f.write(record_3 + '\n')        
        f.write('\n')     
    open('Results/KP-ABE Results.txt', 'r')  
    with open('Results/KP-ABE Results.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return          
    
def run_dpeks(pairing_group, kw_policy, kw_list):

    dpeks_1 = KPabe_search(pairing_group)
    dpeks_1_times, subsets_1 = measure_average_times_dpeks(dpeks_1, kw_list, kw_policy)
    
    dpeks_2 = MZNLHS17(pairing_group)
    dpeks_2_times, subsets_2 = measure_average_times_dpeks(dpeks_2, kw_list, kw_policy)    
    
    n1, n2, m, i = get_par(pairing_group, kw_policy, kw_list, subsets_1)
    print('\n')
    print('*'*62)
    print('Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i))
    print('*'*62)
    algos = ['Setup', 'sKGen', 'TkGen', 'Enc', 'Search']
    algo_string = 'dPEKS {:<10}'.format('') + '  ' + algos[0] + '   ' + algos[1] + '   ' + algos[2] + '    ' + algos[3] + '     ' + algos[4]    
    print('-'*62)
    print(algo_string)
    print('-'*62)
    record_1 = print_running_time_dpeks(dpeks_1.name, dpeks_1_times)    
    record_2 = print_running_time_dpeks(dpeks_2.name, dpeks_2_times) 
    print('-'*62)          
   
    with open('Results/dPEKS Results.txt', 'a') as f:
        f.write('dPEKS: ' + 'Running times (ms) curve MNT224: n1={}  n2={}  m={}  i={}'.format(n1, n2, m, i) + '\n')
        f.write(algo_string + '\n')
        f.write(record_1 + '\n')
        f.write(record_2 + '\n')
        f.write('\n')     
    open('Results/dPEKS Results.txt', 'r')  
    with open('Results/dPEKS Results.txt', 'a') as f:     
        f.write('*' * 62 + '\n')            
    return 

# ------------------------------------------------------ get parameters module ------------------------------------------------
# get parameters of the monotone span program
def get_par(pairing_group, kw_policy, kw_list, subsets):      
    util = SecretUtil(pairing_group) 
    kw_policy = util.createPolicy(kw_policy)   # convert the policy from string to Bin.node format     
     
    msp_obj = MSP(pairing_group)
    mono_span_prog = msp_obj.convert_policy_to_msp(kw_policy)
    keyword_number_one_set = 1
    #nodes = msp_obj.prune(kw_policy[0], kw_list_name)
    
    n1 = len(mono_span_prog) # number of rows
    n2 = msp_obj.len_longest_row # number of columns
    m = len(kw_list) # number of keywords  
    i = len(subsets)

    return n1, n2, m, i

# -------------------------------------------------- Main functions module ---------------------------------------------------    
def wordList_prep(num_words):
    ## Open the file with read only permit
    f = open('./words.txt','r')
    lines = f.readlines()
    
    word_list = []
    #random.seed(1207)
    i = 0
    indices = random.sample(range(1, 400000), num_words)
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
        kw = kw + ':' + str(random.choice(range(1, 1000)))
        kw_list.append(kw)
        attr_list.append(attr)

    choice = [' and ', ' or ']
    indices = random.sample(range(len(word_list)), n_2)
     
    kw_policy, attr_policy = '', '' 
    for i, num in enumerate(indices):
        policy_name = word_list[num]        
        #k = random.choice(choice)    
        
        if i in range(len(indices) - 1):  
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 1000))) + '' + ' AND ' + ''
            attr_policy = attr_policy + policy_name + ' AND ' + ''
        else:       
            kw_policy = kw_policy + policy_name + ':' + str(random.choice(range(1, 1000)))
            attr_policy = attr_policy + policy_name

    return kw_list, kw_policy, attr_list, attr_policy     
    
#------------------------------- Using number as keyword names (attributes) and values ------------------------------------------
#def create_list_and_policy(n_1, n_2):     
    #kw_list = ['1001:1']   
    #for i in range(2, n_1 + 1):
    #    kw_list.append(str(1000 + i) + ':' + str(i))        
        
    #attr_list = ['1']   
    #for i in range(2, n_1 + 1):
    #    attr_list.append(str(i))      
        
    #kw_policy = '1001:1'  
    #policy = '1'          
    #for i in range(2, n_2 + 1):    
    #    choice = [' and ', ' or ']
    #    k = random.choice(choice)      
    #    kw_policy += k + str(1000 + i) + ':' + str(i)
    #    policy += k + str(i)
#--------------------------------------------------------------------------------------------------------------------------------   
        
def main():
    # instantiate a bilinear pairing map
    pairing_group = PairingGroup('MNT224')
    
    # choose a random message
    msg = pairing_group.random(GT)
    
    list_size = [50]
    policy_size = [10, 15, 20, 25, 30, 35, 40, 45, 50]
    
    for size_p in policy_size:
        for size_k in list_size:
            kw_list, kw_policy, attr_list, attr_policy = create_list_and_policy(size_k, size_p)
            
            run_peks(pairing_group, kw_policy, kw_list)
            run_paeks(pairing_group, kw_policy, kw_list)
            run_dpeks(pairing_group, kw_policy, kw_list)
            #run_kpabe(pairing_group, kw_list, kw_policy, attr_list, attr_policy, msg)
      
if __name__ == "__main__":
    debug = True
    main()                 
           
