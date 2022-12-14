import aes

def expand(P):            #tạo khối đầu vào với các thông tin N, A, P
    pt = '1' + P                # và độ dài từng khối, padding '0' nếu cần
    return pt

def CMAC(s, key, Tlen):         #thực hiện qua thuật toán CMAC, tạo tag có 
                                #độ dài Tlen (Tlen < 128)
    
    s = aes.divide(s, 32)       
    y = aes.encrypt(s[0], key)  #mã hóa từng khối của input
    for i in range(1, len(s)):      #output dùng làm input cho vòng tiếp theo
        y = aes.encrypt(s[i], key)
    tag = y[:Tlen]              
    return tag

def ctr(s, n):                  #tạo bộ thanh ghi cho CTR_mode
    counter = []
    counter.append(s)
    for i in range(1, n):
        counter.append(aes.add(s, '1'))
    return counter

def CCM(p, key):
    ctr0 = ''                   #nhập thanh ghi khởi tạo
    x = []
    s = ''
    pt = expand(p)              #tạo khối đầu vào
    tag = CMAC(pt, key, 8)     #thông qua CMAC tạo tag có độ dài 32bit
    counter = ctr(ctr0, len(pt)/32)
    for i in range(0, len(pt)/32):      #mã hóa khối thông qua CTR_mode
        x.append(aes.encrypt(counter[i], key))
    for i in range(1, len(x)):
        s += x[i]
    C = aes.xor_hex(pt, s[:len(pt)]) + aes.xor_hex(tag, x[0][:len(tag)])
    return C

