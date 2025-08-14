import random
from hashlib import sha256

# 假设基础 SM2 实现已导入，包括 point_mul, G, sm2_curve, inverse_mod

def sm2_hash(msg):
    return int(sha256(msg.encode()).hexdigest(), 16)

def sm2_sign_fixed_k(msg, d, k_fixed):
    e = sm2_hash(msg)
    R = point_mul(k_fixed, G)
    r = (e + R.x) % sm2_curve['n']
    s = (inverse_mod(1+d, sm2_curve['n']) * (k_fixed - r*d)) % sm2_curve['n']
    return (r, s, R.x)

# 生成密钥
d = random.randint(1, sm2_curve['n']-1)
P = point_mul(d, G)

# 使用相同的 k 签名两条消息
k_fixed = random.randint(1, sm2_curve['n']-1)
msg1 = "Hello SM2"
msg2 = "Hello SM2 Attack"

r1, s1, Rx1 = sm2_sign_fixed_k(msg1, d, k_fixed)
r2, s2, Rx2 = sm2_sign_fixed_k(msg2, d, k_fixed)

print("签名1:", r1, s1)
print("签名2:", r2, s2)

# 恢复私钥
# s = (k - r*d)/(1+d) mod n  -> d = (k - s*(1+d))/r mod n
# 对两条消息求差
n = sm2_curve['n']
d_recovered = ((s1 - s2) * inverse_mod((r1 - r2) % n, n) - 1) % n
print("原始私钥:", d)
print("恢复私钥:", d_recovered)
print("恢复成功:", d_recovered == d)
