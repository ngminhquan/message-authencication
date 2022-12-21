import aes
import math

#input
#pt = 'dai hoc bach khoa ha noi'
#key = '123456789123456789123456789123456789'

#đưa số thập phân s về chuỗi nhị phân n_bit
def bin_str(s, n):          
    s = bin(s)
    s = s.replace('0b', '')
    a = ''
    while 1:                        #padding các bit '0' vào trước đến khi
        if len(a) + len(s) == n:    #đủ n bit
            a += s
            break
        a += '0'
    return a

def expand(N, A, P, t):
    a = int(len(A)/2)
    n = int(len(N)/2)
    p = int(len(P)/2)      #độ dài chuỗi P được tính theo byte (2 số hexa)
    q = 15 - n
    Q = bin_str(p, 8*q)
    Q = aes.bin_to_hex(Q)
    if a == 0:
        Adata = '0'
    else: Adata = '1'
    flags = '0' + Adata + bin_str(int((t-2)/2), 3) + bin_str(q-1, 3)
    flags = aes.bin_to_hex(flags)
    B0 = flags + N + Q
    #encode value a (độ dài của Ass.Data)
    if 0 < a < math.pow(2, 16) - math.pow(2, 8):
        a_e = aes.bin_to_hex(bin_str(a, 16))
    elif math.pow(2, 16) - math.pow(2, 8) < a < math.pow(2, 32):
        a_e = 'FF' + 'FE' + aes.bin_to_hex(bin_str(a, 32))
    elif math.pow(2, 32) < a < math.pow(2, 64):
        a_e = 'FF' + 'FF' + aes.bin_to_hex(bin_str(a, 64))
    Assdata = a_e + A
    while len(Assdata) % 32 != 0:
        Assdata += '0'
    while len(P) % 32 != 0:
        P += '0'
    b = B0 + Assdata + P
    return b

    
def CMAC(s, key, Tlen):         #thực hiện qua thuật toán CMAC, tạo tag có 
                                #độ dài Tlen (Tlen < 128)
    B = []
    for i in range(0, len(s), 32):
        B.append(s[i:i+32])
    y = aes.encrypt(B[0], key)  #mã hóa từng khối của input
    for i in range(1, len(B)):      #output dùng làm input cho vòng tiếp theo
        y = aes.encrypt(aes.xor_hex(B[i], y), key)
    tag = y[:Tlen]              
    return tag


def ctr_gen(N, P):                  #tạo bộ thanh ghi cho CTR_mode
    n = int(len(N)/2)
    p = int(len(P)/2)      #độ dài chuỗi P được tính theo byte (2 số hexa)
    q = 15 - n
    reserve = '0'
    flags = reserve + reserve + '000' + bin_str(q-1, 3)
    flags = aes.bin_to_hex(flags)
    counter = []
    for i in range(0, int(p/16) +2):
        ctr = flags + N + aes.bin_to_hex(bin_str(i, 8*q))
        counter.append(ctr)
    return counter

def CCM(N, A, P, key, Tlen):
    N = N.upper()
    A = A.upper()
    P = P.upper()
    key = key.upper()
    x = []
    s = ''
    #P = aes.text_to_hex(P)
    pt = expand(N, A, P, int(Tlen/8))              #tạo khối đầu vào
    tag = CMAC(pt, key, int(Tlen/4))     #thông qua CMAC tạo tag có độ dài Tlen_bit
    print('tag: ', tag)
    counter = ctr_gen(N, P)
    print('ct: ', counter)
    for i in range(0, int(len(P)/32) + 2):      #mã hóa khối thông qua CTR_mode
        x.append(aes.encrypt(counter[i], key))
    for i in range(1, len(x)):
        s += x[i]
    C = aes.xor_hex(P, s[:len(P)]) + aes.xor_hex(tag, x[0][:len(tag)])
    return C

#N = '101112131415161718191a1b1c'
#A = ''
#P = '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f'
#Tlen = 112
#key = '404142434445464748494a4b4c4d4e4f'


