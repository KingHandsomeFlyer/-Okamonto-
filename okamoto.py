import random
import hashlib
import sys
import rsa

# math tools


#rabin算法
def rabin_miller(num):
    s = num - 1
    t = 0
    while s % 2 == 0:
        s = s // 2
        t += 1

    for trials in range(5):
        a = random.randrange(2, num - 1)
        v = pow(a, s, num)
        if v != 1:
            i = 0
            while v != (num - 1):
                if i == t - 1:
                    return False
                else:
                    i = i + 1
                    v = (v ** 2) % num
    return True


def is_prime(num):

    # 创建小素数的列表,可以大幅加快速度；如果大数是这些小素数的倍数,那么不是素数,返回false

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
                    89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179,
                    181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277,
                    281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389,
                    397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499,
                    503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617,
                    619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739,
                    743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
                    863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991,997]


    for prime in small_primes:
        if num % prime == 0:
            return False

    # 如果这样没有分辨出来,那么就调用rabin算法
    return rabin_miller(num)


#扩展的欧几里得算法
# 由于考虑到大数运算，因此暂不采用递归写法（栈溢出）
# 最后一个while循环将系数xa+yb=g的系数x取正（考虑到逆元的计算）
def GCD(a, b):
    # initialize x1,y1,x2,y2
    x1, y1, x2, y2 = 1, 0, 0, 1
    tmpa, tmpb = a, b
    while (1):
        # copy t1,t2 from x2,y2
        t1, t2 = x2, y2
        # recursion equations
        x2, y2 = x1 - (a // b) * x2, y1 - (a // b) * y2
        # exchange values
        x1, y1 = t1, t2
        if (a % b) == 0:
            break

        # exchange values
        a, b = b, a % b
    # if b is negative,make it positive
    if b < 0:
        b, x1, y1 = (-1) * b, (-1) * x1, (-1) * y1
    while (x1 <= 0):
        x1 += tmpb
        y1 -= tmpa
    L = (b, x1, y1)
    return L



#这个函数快的话1秒就出结果，慢的话半分钟才出结果
#会是程序中最耗时的算法
def 得到大素数(key_size1=1,key_size2=372):
    while True:
        mul = random.randrange(2 ** key_size1, 2 ** (key_size1 + 1) + 1)
        q   = random.randrange(2 ** key_size2, 2 ** (key_size2 + 1) + 1)
        p = q * mul + 1
        if is_prime(q) and is_prime(p):
            break
    return p,q



def 选取ID(key_size1=11):
    return random.randrange(10 ** key_size1, 10 ** (key_size1 + 1) )


def 选取随机数(q):
    k1 = random.randrange(0, q, 1)
    k2 = random.randrange(0, q, 1)
    return k1, k2


def 选取两个q阶元(p,q):
    div = (p - 1) / q
    base1 = random.randrange(3, 5)
    base2 = random.randrange(2, base1)
    阿尔法一 = base1 ** div
    阿尔法二 = base2 ** div
    return 阿尔法一,阿尔法二


def do_hash(data):
    h = hashlib.sha256()
    h.update(str(data).encode())
    m=h.hexdigest()
    return m


#模拟一个简单的签名过程
def RSA数字签名():
    # 伪随机数生成器
    (pubkey, privkey) = rsa.newkeys(1024)

    with open('public.pem', 'w+') as f:
        f.write(pubkey.save_pkcs1().decode())
    with open('private.pem', 'w+') as f:
        f.write(privkey.save_pkcs1().decode())

    # 导入密钥
    with open('public.pem', 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())
    with open('private.pem', 'r') as f:
        privkey = rsa.PrivateKey.load_pkcs1(f.read().encode())

    return pubkey, privkey


def 签名(ID, v, privkey):
    message = (ID ** 3 + v ** 3) ** 2
    message = str ( do_hash(message) )
    crypto_email_text = rsa.sign(message.encode(), privkey, 'SHA-1')
    return crypto_email_text


def 验证(ID, v, signature, pubkey):
    # 对消息进行签名验证
    message = str( (ID ** 3 + v ** 3) ** 2 )
    message = str(do_hash(message))
    judge = rsa.verify(message.encode(), signature, pubkey)
    if judge:
        print("验证成功")
        return True

    print("验证失败")
    return False

def 选取私钥(q):
    a1 = random.randrange(0,q,1)
    a2 = random.randrange(0,q,1)
    return a1,a2


def 模运算一(a, b, c, d, p):
    总和 = a ** b * c ** d
    g, x, y = GCD(总和, p)
    if g != 1:
        print("gcd != 1, 错误！")
        return -1
    while x <= 0:
        x += 总和
        y += p
    return x


def 模运算二(a, b, c, d, p):
    总和 = a ** b * c ** d
    结果 = 总和 % p
    return 结果


def 选取随机数(t):
    return random.randrange(1, 2 ** t + 1, 1)


def 模运算三(k, a, r, q):
    总和 = k + a * r
    结果 = 总和 % q
    return 结果


def 模运算四(a, b, c, d, e, f, p):
    总和 = a ** b * c ** d * e ** f
    结果 = 总和 % p
    return 结果


# objection


#class Sender:
#   def __init__(self):
#        p,q = 得到大素数(key_size1=2,key_size2=372)
#        选取私钥(1000)



#class Receiver:
#    def __init__(self):
#        e = 选取随机数(random.randrange(2, 6, 1))


#class Authority:
#    def __init__(self):
#        ID = 选取ID(key_size1=11)
#        k1,k2 = 选取随机数(1000)
#        阿尔法一, 阿尔法二 = 选取两个q阶元(p, q)



#main function

if __name__ == '__main__' :
    #Sender Alice
    #Receiver Bob
    #Authority TA


    print("TA开始工作...")
    证书库 = []
    # 对于TA来说:
    p, q = 得到大素数(key_size1=1, key_size2=372)
    print("TA在为Alice选择p、q、α1、α2...")
    阿尔法一, 阿尔法二 = 选取两个q阶元(p, q)
    阿尔法一 = int(阿尔法一)
    阿尔法二 = int(阿尔法二)
    print("TA在为Alice选择ID...")
    AliceID = 选取ID(key_size1=11)
    print()



    print("Alice开始运行")
    # 对于Alice来说:
    print("Alice在选择私钥和随机数...")
    a1, a2 = 选取私钥(64)  # 若选择参数为q，则会导致次数过高，计算机运算不出结果
    k1, k2 = 选取私钥(64)  # 选择私钥的效果也可用以k1和k2的获取

    print("Alice在计算v和r中...")
    v = 模运算一(阿尔法一, a1, 阿尔法二, a2, p)
    r = 模运算二(阿尔法一, k1, 阿尔法二, k2, p)
    print()


    print("TA为Alice签名与颁发证书中...")
    # TA为Alice签名与颁发证书:
    公钥, 私钥 = RSA数字签名()
    Alice签名 = 签名(AliceID, v, 私钥)
    证书库.append([AliceID, v, Alice签名])
    Alice的证书 = [AliceID, v, Alice签名]
    print("颁发完毕...")
    print()


    # 模拟Alice传递消息给Bob
    print("开始检验证书是否有效")
    if 验证(Alice的证书[0], Alice的证书[1], Alice的证书[2], 公钥):
        print("签名验证成功")
    else:
        print("签名验证失败")
        sys.exit()

    e = 选取随机数(random.randrange(2, 6, 1))  # 同理,次数不要太高
    print()


    # 对于Alice来说:
    print("Alice开始运算y1和y2")
    y1 = 模运算三(k1, a1, e, q)
    y2 = 模运算三(k2, a2, e, q)
    print()


    # 对于Bob来说:
    r2 = 模运算四(阿尔法一, y1, 阿尔法二, y2, v, e, p)
    print("Bob开始检验γ是否为γ‘")
    if r == r2:
        print("经检验：Sender为Alice")
        print("Success")

    else:
        print("出现错误")
        print("Fail")


    print()
    print("一个简易的okamoto身份识别程序运行结束")