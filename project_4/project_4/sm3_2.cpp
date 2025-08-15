#include <iostream>
#include <iomanip>
#include <vector>
#include <cstring>
#include <cstdint>
using namespace std;

// -------------------- 常量 --------------------
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

static const uint32_t Tj[64] = {
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x79cc4519,0x79cc4519,0x79cc4519,0x79cc4519,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a,
    0x7a879d8a,0x7a879d8a,0x7a879d8a,0x7a879d8a
};

// -------------------- 宏 --------------------
#define ROTL(x,n) (((x) << (n)) | ((x) >> (32-(n))))
#define FF(x,y,z,j) ((j)<16 ? ((x)^(y)^(z)) : (((x)&(y))|((x)&(z))|((y)&(z))))
#define GG(x,y,z,j) ((j)<16 ? ((x)^(y)^(z)) : (((x)&(y))|((~(x))&(z))))
#define P0(x) ((x)^(ROTL(x,9))^(ROTL(x,17)))
#define P1(x) ((x)^(ROTL(x,15))^(ROTL(x,23)))

// -------------------- 消息填充 --------------------
vector<uint8_t> padding(const uint8_t* message, size_t len) {
    size_t l = len * 8;
    size_t k = (448 - (l + 1)) % 512;
    if (k < 0) k += 512;
    size_t total_len = len + 1 + k / 8 + 8;
    vector<uint8_t> m(total_len, 0);
    memcpy(&m[0], message, len);
    m[len] = 0x80;
    for (int i = 0; i < 8; i++)
        m[total_len - 1 - i] = (l >> (8 * i)) & 0xFF;
    return m;
}

// -------------------- 压缩函数 --------------------
void CF_basic(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++)
        W[i] = (B[i * 4] << 24) | (B[i * 4 + 1] << 16) | (B[i * 4 + 2] << 8) | B[i * 4 + 3];
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B1 = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj[j], j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B1, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C; C = ROTL(B1, 9); B1 = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
    }
    for (int i = 0; i < 8; i++) V[i] ^= (i == 0 ? A : i == 1 ? B1 : i == 2 ? C : i == 3 ? D : i == 4 ? E : i == 5 ? F : i == 6 ? G : H);
}

// -------------------- 基础SM3函数 --------------------
void SM3_basic(const uint8_t* message, size_t len, uint8_t hash[32]) {
    vector<uint8_t> m = padding(message, len);
    uint32_t V[8]; memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < m.size(); i += 64) CF_basic(V, &m[i]);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = V[i] >> 24;
        hash[i * 4 + 1] = V[i] >> 16;
        hash[i * 4 + 2] = V[i] >> 8;
        hash[i * 4 + 3] = V[i];
    }
}

// -------------------- Length Extension Attack --------------------
void SM3_length_extension_attack(const uint8_t* M_prime, size_t M_prime_len,
    const uint32_t H[8], size_t orig_len, uint8_t hash_out[32]) {
    vector<uint8_t> padded_M_prime = padding(M_prime, M_prime_len);

    uint32_t V[8]; memcpy(V, H, sizeof(uint32_t) * 8);

    for (size_t i = 0; i < padded_M_prime.size(); i += 64) {
        CF_basic(V, &padded_M_prime[i]);
    }

    for (int i = 0; i < 8; i++) {
        hash_out[i * 4] = V[i] >> 24;
        hash_out[i * 4 + 1] = V[i] >> 16;
        hash_out[i * 4 + 2] = V[i] >> 8;
        hash_out[i * 4 + 3] = V[i];
    }
}

// -------------------- 工具函数 --------------------
vector<uint8_t> SM3_hash(const vector<uint8_t>& msg) {
    uint8_t hash[32];
    SM3_basic(msg.data(), msg.size(), hash);
    return vector<uint8_t>(hash, hash + 32);
}

// -------------------- 主函数 --------------------
int main() {
    string orig = "message";   // 原消息 M
    string append = "attack";  // 攻击者追加消息 M'

    // 1. 计算原消息哈希
    vector<uint8_t> orig_vec(orig.begin(), orig.end());
    vector<uint8_t> hash_orig = SM3_hash(orig_vec);

    cout << "H(M) = ";
    for (auto b : hash_orig) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << endl;

    // 2. 将原哈希转换为内部状态
    uint32_t H_state[8];
    for (int i = 0; i < 8; i++) {
        H_state[i] = (hash_orig[i * 4] << 24) | (hash_orig[i * 4 + 1] << 16) |
            (hash_orig[i * 4 + 2] << 8) | hash_orig[i * 4 + 3];
    }

    // 3. 执行Length Extension Attack
    uint8_t new_hash[32];
    SM3_length_extension_attack((const uint8_t*)append.c_str(), append.size(),
        H_state, orig_vec.size(), new_hash);

    cout << "H(M||pad(M)||M') = ";
    for (int i = 0; i < 32; i++) cout << hex << setw(2) << setfill('0') << (int)new_hash[i];
    cout << endl;

    // 4. 验证直接计算完整消息哈希
    string full_msg = orig + append;
    vector<uint8_t> full_vec(full_msg.begin(), full_msg.end());
    vector<uint8_t> hash_full = SM3_hash(full_vec);

    cout << "H(M||M') direct = ";
    for (auto b : hash_full) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << endl;

    return 0;
}
