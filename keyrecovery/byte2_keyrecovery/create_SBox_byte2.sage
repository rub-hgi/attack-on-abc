#
#   This sage-file creates the SBox-File "0" with k = 0, used for creating the DDT.
#

import sys
import subprocess
from sage.crypto.block_cipher.patentcipher import Patentcipher
hi = Patentcipher()

try:
    from tqdm import tqdm
    use_tqdm = True
except: 
    use_tqdm = False


def byte2(p,k,rounds=4):
    return byte2_c(p,k,rounds)    

def byte2_c(p,k,rounds=4):
    _stdout = str(subprocess.run("./byte2 "+hex(p)[2:]+" "+hex(k)[2:]+" "+hex(rounds)[2:], shell=True ,capture_output=True))
    start = _stdout.index('stdout=b')+9
    l = 0
    while _stdout[start+l] in [str(i) for i in range(10)]+['a','b','c','d','e','f']:
        l+=1
    if l == 0: print(_stdout)
    stdout = int(_stdout[start:start+l],base=16)
    return stdout


k = 0

cs = []
if use_tqdm: range_ = tqdm(range(2**16))
else: range_ = range(2**16)
for p in range_:
    if not use_tqdm and p & 0x1ff == 0: 
        print(str(100 * (p / len(range_)))[:6]+"% "+"#"* (p // 0x1ff),end="\r")
        sys.stdout.flush()
        
    cs.append(byte2(p,k,1))
if(len(set(cs)) == len(cs)): print("\ngood!")

with open('./0_','w') as f:
    f.write(str(cs))

# print(cs)