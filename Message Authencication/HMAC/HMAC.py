import SHA512 as H

#Thiết lập khóa K+ 1024bit
def pad0(key):
    if len(key) > 256:          #keylen > 1024bit: cho key đi qua hàm băm sha512
        key = H.SHA_512(key)    #để tạo độ dài 512bit
    while len(key) < 256:  
        key += '0'              #padding '0' vào bên trái cho đủ 1024bit (256 so hexa)
    return key

def ip(s):
    ipad = '36'
    while len(ipad) < 256:      #ipad được tạo thành từ các số hexa '36' lặp lại
        ipad += ipad            #1024/8 =128 lần tạo độ dài 1024bit (256 số hexa)
    
    s = H.xor_hex(s, ipad)      #s^ipad tạo khối 1024bit Si nối vào message
    return s

def op(s):
    opad = '5C'                 #opad được tạo thành từ các số hexa '5C' lặp lại
    while len(opad) < 256:      #1024/8 =128 lần tạo độ dài 1024bit (256 số hexa)
        opad += opad
    val = H.xor_hex(s, opad)    #s^opad tạo khối 1024bit So nối vào message
    return val

def HMAC(message, key):
    m = H.text_to_hex(message)  #chuyển từ ASCII về hexa
    key = key.replace(' ', '')
    key = key.replace('\n', '')
    k0 = pad0(key)              #đưa key về khối 1024bit

    ki = ip(k0)                 #XOR K+ với ipad, tạo khối 1024bit ki
    Si = ki + m
    pre = H.SHA_512(Si)         #cho khối Si vừa tạo được đi qua hàm băm sha512
    
    ko = op(k0)                 #XOR K+ với opad, tạo khối 1024bit ko
    So = ko + pre
    tag = H.SHA_512(So)         #tag đầu ra là 512bit
    return tag

with open('input_HMAC.txt', 'r', encoding = 'UTF - 8') as text, open('key_HMAC.txt', 'r', encoding = 'UTF - 8') as key, open('output_HMAC.txt', 'w', encoding = 'UTF - 8') as mac:
    message = text.read()
    key = key.read()
    tag = HMAC(message, key)
    mac.write(tag)


