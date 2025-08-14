#include <iostream>
#include <vector>
#include <string>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iomanip>
#include <queue>
#include <stdexcept>
#include <chrono>
#include <fstream>
#include <sstream>

using namespace std;
using namespace std::chrono;

// ================================ SM3 基础实现 ================================
class SM3 {
public:
    SM3() { reset(); }

    void reset() {
        state[0] = 0x7380166f;
        state[1] = 0x4914b2b9;
        state[2] = 0x172442d7;
        state[3] = 0xda8a0600;
        state[4] = 0xa96f30bc;
        state[5] = 0x163138aa;
        state[6] = 0xe38dee4d;
        state[7] = 0xb0fb0e4e;
        total_len = 0;
        buffer_len = 0;
    }

    void update(const uint8_t* data, size_t len) {
        total_len += len;

        // 处理缓冲区中的剩余数据
        if (buffer_len > 0) {
            size_t copy_len = min(64 - buffer_len, len);
            memcpy(buffer + buffer_len, data, copy_len);
            buffer_len += copy_len;
            data += copy_len;
            len -= copy_len;

            if (buffer_len == 64) {
                compress(buffer);
                buffer_len = 0;
            }
        }

        // 处理完整块
        while (len >= 64) {
            compress(data);
            data += 64;
            len -= 64;
        }

        // 保存剩余数据到缓冲区
        if (len > 0) {
            memcpy(buffer + buffer_len, data, len);
            buffer_len += len;
        }
    }

    void finalize(uint8_t digest[32]) {
        // 添加填充
        uint64_t bit_len = total_len * 8;
        buffer[buffer_len++] = 0x80;

        if (buffer_len > 56) {
            memset(buffer + buffer_len, 0, 64 - buffer_len);
            compress(buffer);
            buffer_len = 0;
        }

        memset(buffer + buffer_len, 0, 56 - buffer_len);
        for (int i = 0; i < 8; ++i) {
            buffer[56 + i] = (bit_len >> (56 - i * 8)) & 0xff;
        }
        compress(buffer);

        // 输出结果
        for (int i = 0; i < 8; ++i) {
            digest[i * 4] = (state[i] >> 24) & 0xff;
            digest[i * 4 + 1] = (state[i] >> 16) & 0xff;
            digest[i * 4 + 2] = (state[i] >> 8) & 0xff;
            digest[i * 4 + 3] = state[i] & 0xff;
        }

        reset();
    }

    // 获取当前状态（用于长度扩展攻击）
    void get_state(uint32_t current_state[8]) const {
        memcpy(current_state, state, 32);
    }

    // 设置状态和总长度（用于长度扩展攻击）
    void set_state(const uint32_t new_state[8], uint64_t len) {
        memcpy(state, new_state, 32);
        total_len = len;
    }

private:
    uint32_t state[8];
    uint64_t total_len;
    uint8_t buffer[64];
    size_t buffer_len;

    // 循环左移
    static uint32_t left_rotate(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }

    // 压缩函数
    void compress(const uint8_t block[64]) {
        uint32_t w[68];
        uint32_t ww[64];

        // 消息扩展
        for (int i = 0; i < 16; ++i) {
            w[i] = (block[i * 4] << 24) | (block[i * 4 + 1] << 16) |
                (block[i * 4 + 2] << 8) | block[i * 4 + 3];
        }

        for (int i = 16; i < 68; ++i) {
            w[i] = p1(w[i - 16] ^ w[i - 9] ^ left_rotate(w[i - 3], 15)) ^
                left_rotate(w[i - 13], 7) ^ w[i - 6];
        }

        for (int i = 0; i < 64; ++i) {
            ww[i] = w[i] ^ w[i + 4];
        }

        uint32_t a = state[0];
        uint32_t b = state[1];
        uint32_t c = state[2];
        uint32_t d = state[3];
        uint32_t e = state[4];
        uint32_t f = state[5];
        uint32_t g = state[6];
        uint32_t h = state[7];

        // 迭代压缩
        for (int i = 0; i < 64; ++i) {
            uint32_t ss1, ss2, tt1, tt2;

            ss1 = left_rotate(left_rotate(a, 12) + e + left_rotate(t(i), i), 7);
            ss2 = ss1 ^ left_rotate(a, 12);
            tt1 = ff(i, a, b, c) + d + ss2 + ww[i];
            tt2 = gg(i, e, f, g) + h + ss1 + w[i];
            d = c;
            c = left_rotate(b, 9);
            b = a;
            a = tt1;
            h = g;
            g = left_rotate(f, 19);
            f = e;
            e = p0(tt2);
        }

        state[0] ^= a;
        state[1] ^= b;
        state[2] ^= c;
        state[3] ^= d;
        state[4] ^= e;
        state[5] ^= f;
        state[6] ^= g;
        state[7] ^= h;
    }

    // 辅助函数
    static uint32_t ff(int j, uint32_t x, uint32_t y, uint32_t z) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (x & z) | (y & z);
    }

    static uint32_t gg(int j, uint32_t x, uint32_t y, uint32_t z) {
        if (j < 16) return x ^ y ^ z;
        return (x & y) | (~x & z);
    }

    static uint32_t p0(uint32_t x) {
        return x ^ left_rotate(x, 9) ^ left_rotate(x, 17);
    }

    static uint32_t p1(uint32_t x) {
        return x ^ left_rotate(x, 15) ^ left_rotate(x, 23);
    }

    static uint32_t t(int j) {
        if (j < 16) return 0x79cc4519;
        return 0x7a879d8a;
    }
};

// ================================ 辅助函数 ================================
string hexdigest(const uint8_t* digest, size_t len) {
    stringstream ss;
    ss << hex << setfill('0');
    for (size_t i = 0; i < len; ++i) {
        ss << setw(2) << static_cast<int>(digest[i]);
    }
    return ss.str();
}

// ================================ 长度扩展攻击 ================================

void length_extension_attack() {
    cout << "\n===== Length Extension Attack Demo =====\n";

    // 原始消息和哈希
    string secret = "secret_data";
    string original_msg = "user=admin";
    uint8_t orig_hash[32];

    // 计算原始哈希
    SM3 sm3;
    sm3.update((const uint8_t*)original_msg.data(), original_msg.size()); // 确保传递两个参数
    sm3.finalize(orig_hash);

    cout << "Original Message: " << original_msg << endl;
    cout << "Original Hash:    " << hexdigest(orig_hash, 32) << endl;

    // 攻击者知道：original_msg的长度和orig_hash，但不知道secret
    // 构造扩展消息
    string extension = "&access=admin";

    // 1. 计算填充长度
    size_t orig_len = original_msg.size();
    size_t total_len_with_secret = secret.size() + orig_len;

    // 计算填充长度 (基于secret + original_msg的总长度)
    size_t padding_len = 64 - (total_len_with_secret % 64);
    if (padding_len < 9) padding_len += 64;

    // 2. 创建新消息: 原始消息 + 填充 + 扩展
    vector<uint8_t> new_msg;
    new_msg.insert(new_msg.end(), original_msg.begin(), original_msg.end());
    new_msg.push_back(0x80); // 添加起始填充

    // 添加填充的0字节
    padding_len--; // 减去0x80占用的1字节
    padding_len -= 8; // 为长度字段预留8字节
    new_msg.insert(new_msg.end(), padding_len, 0);

    // 添加长度字段 (总比特数 = (secret + original_msg) * 8)
    uint64_t total_bits = total_len_with_secret * 8;
    for (int i = 7; i >= 0; i--) {
        new_msg.push_back((total_bits >> (i * 8)) & 0xFF);
    }

    // 添加扩展
    new_msg.insert(new_msg.end(), extension.begin(), extension.end());

    // 3. 设置SM3状态
    SM3 forged_sm3;
    uint32_t state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = (orig_hash[i * 4] << 24) | (orig_hash[i * 4 + 1] << 16) |
            (orig_hash[i * 4 + 2] << 8) | orig_hash[i * 4 + 3];
    }

    // 设置初始状态和消息长度 (secret + original_msg + padding)
    forged_sm3.set_state(state, total_len_with_secret + padding_len + 1 + 8);

    // 4. 计算扩展部分的哈希
    forged_sm3.update((const uint8_t*)extension.data(), extension.size()); // 确保传递两个参数
    uint8_t forged_hash[32];
    forged_sm3.finalize(forged_hash);

    cout << "Forged Hash:      " << hexdigest(forged_hash, 32) << endl;

    // 验证攻击是否成功
    // 计算正确的新消息哈希 (secret + original_msg + padding + extension)
    SM3 valid_sm3;
    string full_msg = secret + string(new_msg.begin(), new_msg.end());
    valid_sm3.update((const uint8_t*)full_msg.data(), full_msg.size());
    uint8_t valid_hash[32];
    valid_sm3.finalize(valid_hash);

    cout << "Valid Hash:       " << hexdigest(valid_hash, 32) << endl;

    // 比较结果
    bool success = memcmp(forged_hash, valid_hash, 32) == 0;
    cout << "Attack Result:    " << (success ? "SUCCESS" : "FAILED") << endl;
}

// ================================ Merkle 树实现 ================================
class MerkleTree {
public:
    MerkleTree(const vector<vector<uint8_t>>& leaves) {
        if (leaves.empty()) throw invalid_argument("No leaves provided");

        // 创建叶子节点
        for (const auto& leaf : leaves) {
            nodes.push_back(hash(leaf));
        }

        leaf_count = nodes.size();

        // 构建树
        build_tree();
    }

    // 获取根哈希
    vector<uint8_t> root_hash() const {
        return nodes.empty() ? vector<uint8_t>(32, 0) : nodes[0];
    }

    // 存在性证明
    vector<pair<vector<uint8_t>, bool>> proof_of_existence(size_t index) const {
        vector<pair<vector<uint8_t>, bool>> proof;
        if (index >= leaf_count) {
            throw out_of_range("Leaf index out of range");
        }

        // 从叶子节点开始（在nodes数组中的位置）
        size_t idx = nodes.size() - leaf_count + index;

        while (idx > 0) {
            // 计算父节点位置
            size_t parent = (idx - 1) / 2;

            // 确定兄弟节点位置
            size_t sibling;
            if (idx % 2 == 1) { // 左子节点
                sibling = idx + 1;
            }
            else { // 右子节点
                sibling = idx - 1;
            }

            // 如果兄弟节点存在
            if (sibling < nodes.size()) {
                // 如果当前节点是左子节点，兄弟节点在右边
                // 如果当前节点是右子节点，兄弟节点在左边
                proof.emplace_back(nodes[sibling], idx % 2 == 1);
            }

            // 移动到父节点
            idx = parent;
        }

        return proof;
    }

    // 验证存在性证明
    static bool verify_existence(const vector<uint8_t>& leaf,
        const vector<uint8_t>& root,
        const vector<pair<vector<uint8_t>, bool>>& proof) {
        vector<uint8_t> current = hash(leaf);

        for (const auto& [hash_val, is_left] : proof) {
            if (is_left) {
                // 当前节点是左子节点，兄弟节点在右边
                current = hash_pair(current, hash_val);
            }
            else {
                // 当前节点是右子节点，兄弟节点在左边
                current = hash_pair(hash_val, current);
            }
        }

        return current == root;
    }

private:
    vector<vector<uint8_t>> nodes;
    size_t leaf_count;

    // 构建Merkle树
    void build_tree() {
        if (nodes.size() == 1) return;

        vector<vector<uint8_t>> current_level = nodes;
        nodes.clear();

        while (current_level.size() > 1) {
            vector<vector<uint8_t>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                const auto& left = current_level[i];
                const auto& right = (i + 1 < current_level.size()) ? current_level[i + 1] : left;
                next_level.push_back(hash_pair(left, right));
            }

            // 保存当前层节点（从后往前存储）
            nodes.insert(nodes.begin(), next_level.begin(), next_level.end());
            current_level = move(next_level);
        }

        // 根节点在nodes[0]
    }

    // 计算哈希
    static vector<uint8_t> hash(const vector<uint8_t>& data) {
        SM3 sm3;
        sm3.update(data.data(), data.size());
        vector<uint8_t> digest(32);
        sm3.finalize(digest.data());
        return digest;
    }

    // 计算两个节点的哈希
    static vector<uint8_t> hash_pair(const vector<uint8_t>& left, const vector<uint8_t>& right) {
        vector<uint8_t> combined = left;
        combined.insert(combined.end(), right.begin(), right.end());
        return hash(combined);
    }
};

// ================================ 测试函数 ================================
void test_sm3() {
    cout << "===== SM3 Implementation Test =====" << endl;

    vector<pair<string, string>> test_vectors = {
        {"abc", "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
        {"", "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b"},
        {"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
         "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"}
    };

    SM3 sm3;

    for (const auto& [input, expected] : test_vectors) {
        sm3.reset();
        sm3.update(reinterpret_cast<const uint8_t*>(input.data()), input.size());
        uint8_t digest[32];
        sm3.finalize(digest);
        string result = hexdigest(digest, 32);

        cout << "Input: \"" << input << "\""
            << "\nExpected: " << expected
            << "\nActual:   " << result
            << "\nResult:   " << (result == expected ? "PASS" : "FAIL")
            << "\n" << endl;
    }
}

void performance_test() {
    cout << "===== SM3 Performance Test =====" << endl;

    const size_t SIZE = 10 * 1024 * 1024; // 10MB
    vector<uint8_t> data(SIZE, 0x61); // 'a'

    SM3 sm3;

    auto start = high_resolution_clock::now();
    sm3.update(data.data(), data.size());
    uint8_t digest[32];
    sm3.finalize(digest);
    auto end = high_resolution_clock::now();

    auto duration = duration_cast<milliseconds>(end - start);
    double speed = (double)SIZE / duration.count() / 1024; // MB/s

    cout << "Data Size: " << SIZE / 1024 << " KB" << endl;
    cout << "Time:      " << duration.count() << " ms" << endl;
    cout << "Speed:     " << fixed << setprecision(2) << speed << " MB/s" << endl;
    cout << "Hash:      " << hexdigest(digest, 32) << endl;
}

void test_merkle_tree() {
    cout << "\n===== Merkle Tree Test =====" << endl;

    // 生成10个叶子节点（演示用）
    const size_t LEAF_COUNT = 10;
    vector<vector<uint8_t>> leaves;
    for (size_t i = 0; i < LEAF_COUNT; ++i) {
        string leaf = "leaf_" + to_string(i);
        leaves.push_back(vector<uint8_t>(leaf.begin(), leaf.end()));
    }

    // 构建Merkle树
    MerkleTree tree(leaves);
    auto root = tree.root_hash();
    cout << "Merkle Root: " << hexdigest(root.data(), root.size()) << endl;

    // 存在性证明
    size_t test_index = 3;
    cout << "\nExistence Proof for leaf " << test_index << ":" << endl;

    auto proof = tree.proof_of_existence(test_index);
    bool valid = MerkleTree::verify_existence(leaves[test_index], root, proof);

    cout << "Proof Size: " << proof.size() << " nodes" << endl;
    cout << "Proof Valid: " << (valid ? "YES" : "NO") << endl;

    // 尝试验证错误的叶子节点
    vector<uint8_t> wrong_leaf = { 'x', 'y', 'z' };
    bool invalid_result = MerkleTree::verify_existence(wrong_leaf, root, proof);
    cout << "Verify Wrong Leaf: " << (invalid_result ? "INCORRECT" : "CORRECT") << endl;
}

// ================================ 主函数 ================================
int main() {
    cout << "SM3 Implementation in Visual Studio\n" << endl;

    // 基础测试
    test_sm3();

    // 性能测试
    performance_test();

    // 长度扩展攻击演示
    length_extension_attack();

    // Merkle树测试
    test_merkle_tree();

    cout << "\nAll tests completed." << endl;
    return 0;
}