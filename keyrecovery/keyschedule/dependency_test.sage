#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#
#
#   This file was used to create the dependencymatrix-figure in the paper. 
#   It is not a direct part in the keyrecovery process, but rather a tool for tex-file generation.
#
# draw: if true, the matrix will be printed as compilable LaTeX code
# -> run with: sage dependency_test.sage > ../../../tex/graphics/dependency_matrix.tex
# greedy: if true, the matrix will be printed, so that it can be used as input for the greedy algorithm
#       (to find the most efficient strategy)
#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~#

draw = True
greedy = False

from sage.crypto.sbox import SBox
from sage.rings.integer_ring import ZZ
from sage.structure.sage_object import SageObject
from sage.modules.free_module_element import vector
from sage.modules.vector_mod2_dense import Vector_mod2_dense
from sage.rings.finite_rings.finite_field_constructor import GF
from sage.crypto.block_cipher.patentcipher import Patentcipher
hi = Patentcipher()
import random

import sys
sys.path.append('/Library/Frameworks/Python.framework/Versions/3.11/lib/python3.11/site-packages')

import importlib
if importlib.util.find_spec("tqdm") != None:
    imported = True
    from tqdm import tqdm
else: imported = False

def maximum(a,b):
    if(a>b): return a
    else: return b


N_global = 100

def printC(C):

    print("\n\t"+" "*13,end="")
    for j in range(128):
        if j % 8 == 0: print("\t",end="")
        print(f"{hex(j)[2:]: <2}",end=" ")
    print()
    for i in range(128):
        if(i%8 == 0): print()

        if(i%16 < 8): print(f"Byte2 RK{i//16}[{i%8: >2}]:", end="\t")
        else: print(f"Byte4 RK{i//16}[{i%8: >2}]:", end="\t")
        for j in range(128):
            if j % 8 == 0: print("\t",end="")
            if C[i][j] == 0:
                print(f"_ ", end =" ")
            else: print(f"# ", end =" ")
        print()
    print()


def intToBitVec(n_):
    n = n_
    result = []
    while n>0:
        result.append(n & 1)
        n >>= 1
    return [0]*(128-len(result))+ result[::-1]


def keyschedule(mk):
    roundkeys = hi.keyschedule(mk,rounds=8,vec=False)
    tmp = [roundkeys[i][4:6]+roundkeys[i][8:10] for i in range(8)]
    return int(''.join(tmp),16)
    





def generic_dependency_test(function=keyschedule,N=N_global, MK_size=128,RK_size=128,knownpos=[[0,128]]):

    C = [[0 for i in range(MK_size)] for j in range(RK_size)] # C(i,j) 
    
    E = [(1<<(127-i)) for i in range(MK_size)]
    
    for _ in tqdm(range(N)):

        MK_int = random.randint(0,2**MK_size-1)
        c = intToBitVec(function(MK_int))
        
        for t_bit in range(MK_size):

            c_ = intToBitVec(function(MK_int^^E[t_bit]))
            for bit in range(RK_size):
                if c[bit] != c_[bit]:
                    C[bit][t_bit] = 1
    return C


PR = BooleanPolynomialRing(128,names='mk')
mk = vector(PR,PR.gens())


C = generic_dependency_test(keyschedule,knownpos=[])

if greedy:
    C = [[0,c] for c in C]    
    print(C)
elif draw:
    
    print("\\documentclass{standalone}")
    print("\\usepackage{amsmath}")
    print("\\usepackage{amssymb}")
    print("\\usepackage{amsthm}")
    print("\\usepackage{bm}")
    print("\\usepackage{tikz}")
    print("\\usepackage[margin=2cm]{geometry}")
    print("\\usepackage{pgfplots}")
    print("\\pgfplotsset{compat=1.18}")
    print("\\usetikzlibrary{calc}")
    print("\\usetikzlibrary{positioning, fit, shapes.geometric, decorations.text}")
    print("\\usetikzlibrary{decorations.pathreplacing,calligraphy}")
    print("\\usetikzlibrary{patterns}")
    print("\\usetikzlibrary{arrows}")
    print("\\usetikzlibrary{calc}")
    print("\\newcommand*{\\sq}[2][]{\\draw[fill]  (#1 - 0.5,#2 - 0.5) rectangle (#1 + 0.5,#2 + 0.5);}")
    print("\n\n")
    print("\\begin{document}")
    print("\\begin{tikzpicture}")
    for i in range(128):
        for j in range(128):
            if(C[i][j] == 1):
                print("\\sq["+str(j)+"]{"+str(i)+"}")

    print("\\end{tikzpicture}")
    print("\\end{document}")



else:
    printC(C)
exit()
