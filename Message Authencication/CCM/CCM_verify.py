import aes
import CCM

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
    if len(C) < Tlen/4:             #chuyển về INVALID nếu Clen< Tlen
        return 'INVALID1'

    m = int(Clen/32) - int(Tlen/128)
    counter = ctrgen(N, m)     
    
    #encrypt các thanh ghi ctr
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
        return aes.hex_to_text(P)

N = '101112131415161718191a1b1c'
A = '0001020304050607'
C = '2DD116AE52CE833020208BD5720BED210BF1A74DBA9F159A75ABC98D'
Tlen = 32
key = '404142434445464748494a4b4c4d4e4f'

print(CCM_verify(C, N, A, key, Tlen))


