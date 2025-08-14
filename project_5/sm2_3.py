import random
from hashlib import sha256

# 假设基础 SM2 已实现：point_add, point_mul, G, sm2_curve, Point

def sm2_hash(msg):
    return int(sha256(msg.encode()).hexdigest(), 16)

# 生成私钥公钥（被攻击者）
d = random.randint(1, sm2_curve['n']-1)
P = point_mul(d, G)

n = sm2_curve['n']

# 1. 选择随机 u, v
u = random.randint(1, n-1)
v = random.randint(1, n-1)

# 2. 构造伪造点 R = u*G + v*P
R = point_add(point_mul(u, G), point_mul(v, P), sm2_curve)

# 3. 构造伪造签名
r = R.x % n
s = (r * pow(u, -1, n)) % n

# 4. 构造对应消息哈希 e，使验签通过
e = (r * v * pow(u, -1, n)) % n

msg = f"Message with fake hash {e}"

# 5. 验证伪造签名
t = (r + s) % n
R_check = point_add(point_mul(s, G), point_mul(t, P), sm2_curve)
valid = r == R_check.x % n

print("伪造签名 r,s:", r, s)
print("伪造消息哈希 e:", e)
print("验签是否通过:", valid)
