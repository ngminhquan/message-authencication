import aes

def expand(P):                  #tạo khối đầu vào với các thông tin N, A, P
    pt = '1' + P                ## và độ dài từng khối, padding '0' nếu cần
    return pt

def ctr(s, n):                  #tạo bộ thanh ghi cho CTR_mode
    counter = []
    counter.append(s)
    for i in range(1, n):
        counter.append(aes.add(s, '1'))
    return counter

def CMAC_dec(s, key):           #giải mã thông qua CMAC
    B = aes.divide(s, 32)          
    y = aes.encrypt(B[0], key)          #mã hóa khối input[0]
    for i in range(1, len(s)/32):       #lấy output XOR với khối input tiếp theo
        y = aes.encrypt(aes.xor_hex(B[i], y), key)
    return y

def CCM_verify(C, N, A, key, ctr0, Tlen):
    Clen = len(C)
    x = []
    s = ''
    if len(C) < Tlen:
        return 'INVALID'
    counter = ctr(ctr0, Clen/32)           
    for i in range(0, Clen/32):
        x.append(aes.encrypt(counter[i], key))
    for i in range(1, len(x)):
        s += x[i]
    P = aes.xor_hex(C[:Clen - Tlen], s[:Clen - Tlen])
    tag = aes.xor_hex(C[Clen - Tlen:], x[0][Tlen])
    pt = expand(N, A, P)
    y = CMAC_dec(pt, key)
    if tag != y[:Tlen]:
        return 'INVALID'
    else:
        return P


