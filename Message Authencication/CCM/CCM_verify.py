import aes
import CCM

def CMAC_dec(s, key, Tlen):
    B = []
    for i in range(0, len(s), 32):
        B.append(s[i:i+32])
    y = aes.encrypt(B[0], key)
    for i in range(1, len(B)):
        y = aes.encrypt(aes.xor_hex(B[i], y), key)
    tag = y[:Tlen]              
    return tag


def ctrgen(N, m):                  #tạo bộ thanh ghi cho CTR_mode
    n = int(len(N)/2)       #độ dài chuỗi được tính theo byte (2 số hexa)
    q = 15 - n
    reserve = '0'
    flags = reserve + reserve + '000' + CCM.bin_str(q-1, 3)
    flags = aes.bin_to_hex(flags)
    counter = []
    for i in range(0, m +2):
        ctr = flags + N + aes.bin_to_hex(CCM.bin_str(i, 8*q))
        counter.append(ctr)
    return counter

def CCM_verify(C, N, A, key, Tlen):
    N = N.upper()
    A = A.upper()
    C = C.upper()
    key = key.upper()
    Clen = len(C)
    
    x = []
    s = ''
    if len(C) < Tlen/4:
        return 'INVALID1'
    m = int(Clen/32) - int(Tlen/128)
    counter = ctrgen(N, m)     
    
    for i in range(0, m + 2):
        x.append(aes.encrypt(counter[i], key))
    for i in range(1, len(x)):
        s += x[i]
    P = aes.xor_hex(C[:Clen - int(Tlen/4)], s[:Clen - int(Tlen/4)])
    tag = aes.xor_hex(C[Clen - int(Tlen/4):], x[0][:int(Tlen/4)])
    pt = CCM.expand(N, A, P, int(Tlen/8))
    y = CCM.CMAC(pt, key, int(Tlen/4))
    print('tag', tag)
    print('y: ', y)
    if tag != y[:Tlen]:
        return 'INVALID2'
    else:
        return P

N = '10111213141516'
A = '0001020304050607'
C = '7162015b4dac255d'
Tlen = 32
key = '404142434445464748494a4b4c4d4e4f'

print(CCM_verify(C, N, A, key, Tlen))


