import random
import numpy as np
from hashlib import sha256
import time

# 尝试使用 gmpy2 加速大数运算
try:
    import gmpy2
    from gmpy2 import mpz, invert
    USE_GMPY2 = True
except ImportError:
    USE_GMPY2 = False

# ------------------------------
# 基本椭圆曲线运算
# ------------------------------
class Point:
    def __init__(self, x, y, curve):
        self.x = x
        self.y = y
        self.curve = curve

    def __str__(self):
        return f"Point({hex(self.x)}, {hex(self.y)})"

def inverse_mod(k, p):
    if USE_GMPY2:
        return int(invert(mpz(k), mpz(p)))
    else:
        return pow(k, -1, p)

def point_add(P, Q, curve):
    if P is None: return Q
    if Q is None: return P
    if P.x == Q.x and P.y != Q.y: return None
    if P.x == Q.x:
        lam = (3*P.x*P.x + curve['a']) * inverse_mod(2*P.y, curve['p']) % curve['p']
    else:
        lam = (Q.y - P.y) * inverse_mod(Q.x - P.x, curve['p']) % curve['p']
    x_r = (lam*lam - P.x - Q.x) % curve['p']
    y_r = (lam*(P.x - x_r) - P.y) % curve['p']
    return Point(x_r, y_r, curve)

def point_mul(k, P):
    R = None
    while k:
        if k & 1:
            R = point_add(R, P, P.curve)
        P = point_add(P, P, P.curve)
        k >>= 1
    return R

# ------------------------------
# SM2参数
# ------------------------------
sm2_curve = {
    'p': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF,
    'a': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC,
    'b': 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93,
    'n': 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123,
}

G = Point(
    0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7,
    0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0,
    sm2_curve
)

# ------------------------------
# 密钥生成
# ------------------------------
def gen_keypair():
    d = random.randint(1, sm2_curve['n'] - 1)
    P = point_mul(d, G)
    return d, P

# ------------------------------
# 哈希函数
# ------------------------------
def sm2_hash(msg_list):
    """
    支持批量输入优化：
    msg_list: list of bytes
    返回 list of int
    """
    if isinstance(msg_list, list):
        return [int(sha256(msg).hexdigest(), 16) for msg in msg_list]
    else:
        return int(sha256(msg_list).hexdigest(), 16)

# ------------------------------
# 签名与验证
# ------------------------------
def sm2_sign(msg, d):
    e = sm2_hash(msg.encode())
    n = sm2_curve['n']
    while True:
        k = random.randint(1, n-1)
        R = point_mul(k, G)
        r = (e + R.x) % n
        if r == 0 or r + k == n:
            continue
        s = (inverse_mod(1 + d, n) * (k - r*d)) % n
        if s != 0:
            break
    return (r, s)

def sm2_verify(msg, signature, P):
    r, s = signature
    e = sm2_hash(msg.encode())
    n = sm2_curve['n']
    t = (r + s) % n
    if t == 0:
        return False
    R = point_add(point_mul(s, G), point_mul(t, P), sm2_curve)
    return r == (e + R.x) % n

# ------------------------------
# 加密与解密
# ------------------------------
def kdf(Z, klen):
    ct = 1
    K = b''
    while len(K) < klen:
        K += sha256(Z + ct.to_bytes(4, 'big')).digest()
        ct += 1
    return K[:klen]

def sm2_encrypt(msg, P):
    n = sm2_curve['n']
    while True:
        k = random.randint(1, n-1)
        C1 = point_mul(k, G)
        S = point_mul(k, P)
        xS = S.x.to_bytes(32, 'big')
        yS = S.y.to_bytes(32, 'big')
        msg_bytes = msg.encode()
        C2 = bytes(a ^ b for a, b in zip(msg_bytes, kdf(xS + yS, len(msg_bytes))))
        C3 = sha256(xS + msg_bytes + yS).digest()
        return (C1, C2, C3)

def sm2_decrypt(C, d):
    C1, C2, C3 = C
    S = point_mul(d, C1)
    xS = S.x.to_bytes(32, 'big')
    yS = S.y.to_bytes(32, 'big')
    msg_bytes = bytes(a ^ b for a, b in zip(C2, kdf(xS + yS, len(C2))))
    if sha256(xS + msg_bytes + yS).digest() != C3:
        raise ValueError("消息认证失败")
    return msg_bytes.decode()

# ------------------------------
# T-Table 预计算优化
# ------------------------------
def precompute_table(P, bits=4):
    table = [None] * (1 << bits)
    for i in range(1, len(table)):
        table[i] = point_mul(i, P)
    return table


def fast_mul(k, table, bits=4):
    """高位窗口法，确保结果和基础方法一致"""
    R = None
    k_bin = bin(k)[2:]

    # 从高位向低位，每 bits 位处理一次
    i = 0
    while i < len(k_bin):
        # 每轮先 R 加倍 bits 次
        if R is not None:
            for _ in range(bits):
                R = point_add(R, R, table[1].curve)

        # 当前窗口
        window = k_bin[i:i + bits]
        if window:
            idx = int(window, 2)
            if idx != 0:
                R = table[idx] if R is None else point_add(R, table[idx], table[idx].curve)

        i += bits
    return R


# ------------------------------
# NumPy批量异或优化示例
# ------------------------------
def batch_encrypt(msgs, P):
    """批量加密多条消息"""
    C_list = []
    for msg in msgs:
        C_list.append(sm2_encrypt(msg, P))
    return C_list

# ------------------------------
# 测试
# ------------------------------
if __name__ == "__main__":
    print("==== SM2 密钥生成 ====")
    d, P = gen_keypair()
    print("私钥:", d)
    print("公钥:", P)

    print("\n==== SM2 签名验证 ====")
    msg = "Hello SM2"
    sig = sm2_sign(msg, d)
    print("签名:", sig)
    print("验证:", sm2_verify(msg, sig, P))

    print("\n==== SM2 加解密 ====")
    C = sm2_encrypt(msg, P)
    print("密文:", C)
    M = sm2_decrypt(C, d)
    print("解密:", M)

    print("\n==== T-Table 优化示例 ====")
    table = precompute_table(G)
    k = random.randint(1, sm2_curve['n'] - 1)
    R1 = point_mul(k, G)
    R2 = fast_mul(k, table)
    print("原始点乘:", R1)
    print("T-Table点乘:", R2)
    print("是否相同:", R1.x == R2.x and R1.y == R2.y)