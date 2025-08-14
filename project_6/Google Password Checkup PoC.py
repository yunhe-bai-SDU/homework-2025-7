import hashlib
import random

# ===========================
# 模拟泄露密码数据库
# ===========================
leaked_passwords = [
    "123456", "password", "qwerty", "abc123", "letmein",
    "admin", "welcome", "monkey", "dragon", "iloveyou"
]


def hash_password(pwd):
    """使用 SHA-256 对密码进行哈希"""
    return hashlib.sha256(pwd.encode()).hexdigest()


# 将泄露密码存入数据库（哈希形式）
leaked_db = set(hash_password(p) for p in leaked_passwords)


# ===========================
# 用户端实现
# ===========================
def user_generate_hash(password, bucket_size=4):
    """
    用户生成密码哈希，并模拟 k-匿名分桶
    bucket_size: 分桶前 n 位
    """
    h = hash_password(password)
    bucket_prefix = h[:bucket_size]  # k-匿名分桶（取前 n 位）
    return bucket_prefix, h


# ===========================
# 服务器端实现
# ===========================
def server_check_password(user_bucket_prefix, user_hash, bucket_size=4):
    """
    服务器根据用户的分桶前缀，返回泄露情况
    """
    # 找到所有属于同一分桶的泄露密码
    candidate_hashes = [p for p in leaked_db if p[:bucket_size] == user_bucket_prefix]

    # 判断用户哈希是否在泄露库中
    return user_hash in candidate_hashes


# ===========================
# PoC 测试
# ===========================
if __name__ == "__main__":
    test_passwords = ["123456", "safePassword!", "qwerty", "newpass2025", "letmein"]

    bucket_size = 4  # 模拟 k-匿名分桶前 n 位

    print("=== Google Password Checkup PoC ===")
    for pwd in test_passwords:
        bucket_prefix, h = user_generate_hash(pwd, bucket_size)
        leaked = server_check_password(bucket_prefix, h, bucket_size)
        print(f"密码 '{pwd}' 是否泄露? {'是' if leaked else '否'}")

    # 批量查询示例
    print("\n=== 批量查询示例 ===")
    batch_passwords = ["admin", "welcome", "monkey", "securePass1"]
    results = {}
    for pwd in batch_passwords:
        bucket_prefix, h = user_generate_hash(pwd, bucket_size)
        results[pwd] = server_check_password(bucket_prefix, h, bucket_size)

    for pwd, leaked in results.items():
        print(f"密码 '{pwd}' 是否泄露? {'是' if leaked else '否'}")
