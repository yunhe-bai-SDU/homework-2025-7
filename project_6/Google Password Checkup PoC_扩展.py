import hashlib
import random
import matplotlib.pyplot as plt

# ===========================
# 模拟泄露密码数据库
# ===========================
leaked_passwords = [
    "123456", "password", "qwerty", "abc123", "letmein",
    "admin", "welcome", "monkey", "dragon", "iloveyou",
    "trustno1", "sunshine", "football", "master", "shadow"
]

def hash_password(pwd):
    """使用 SHA-256 对密码进行哈希"""
    return hashlib.sha256(pwd.encode()).hexdigest()

# 哈希存储泄露密码
leaked_db = [hash_password(p) for p in leaked_passwords]

# 构建分桶索引（k-匿名）
def build_bucket_index(db, bucket_size=4):
    """将哈希按前 bucket_size 位分桶"""
    bucket_index = {}
    for h in db:
        prefix = h[:bucket_size]
        if prefix not in bucket_index:
            bucket_index[prefix] = []
        bucket_index[prefix].append(h)
    return bucket_index

bucket_size = 4
bucket_index = build_bucket_index(leaked_db, bucket_size)

# ===========================
# 用户端
# ===========================
def user_generate_hash_batch(passwords, bucket_size=4):
    """
    批量生成哈希及分桶标识
    返回列表 [(password, bucket_prefix, full_hash)]
    """
    result = []
    for pwd in passwords:
        h = hash_password(pwd)
        prefix = h[:bucket_size]
        result.append((pwd, prefix, h))
    return result

# ===========================
# 服务器端
# ===========================
def server_check_batch(user_hash_list, bucket_index, bucket_size=4):
    """
    批量匹配用户密码
    返回 dict {password: True/False}
    """
    results = {}
    for pwd, prefix, h in user_hash_list:
        candidate_hashes = bucket_index.get(prefix, [])
        results[pwd] = h in candidate_hashes
    return results

# ===========================
# 可视化结果
# ===========================
def visualize_results(results):
    leaked_count = sum(1 for v in results.values() if v)
    safe_count = len(results) - leaked_count

    plt.figure(figsize=(6,6))
    plt.pie([leaked_count, safe_count], labels=["泄露", "安全"], autopct='%1.1f%%', colors=["red","green"])
    plt.title("密码泄露检测结果")
    plt.show()

    # 条形图显示每条密码状态
    plt.figure(figsize=(10,4))
    passwords = list(results.keys())
    status = [1 if results[p] else 0 for p in passwords]
    plt.bar(passwords, status, color=["red" if v else "green" for v in status])
    plt.ylabel("是否泄露 (1=泄露,0=安全)")
    plt.title("每条密码状态")
    plt.show()

# ===========================
# PoC 测试
# ===========================
if __name__ == "__main__":
    test_passwords = ["123456", "safePassword!", "qwerty", "newpass2025", "letmein", "dragon", "secure123"]

    # 用户端生成批量哈希
    user_batch = user_generate_hash_batch(test_passwords, bucket_size)

    # 服务器端批量匹配
    results = server_check_batch(user_batch, bucket_index, bucket_size)

    # 打印结果
    print("=== 批量密码泄露检测结果 ===")
    for pwd, leaked in results.items():
        print(f"密码 '{pwd}' 是否泄露? {'是' if leaked else '否'}")

    # 可视化
    visualize_results(results)
