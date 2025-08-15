#include <iostream>
#include <iomanip>
#include <cstring>
#include <vector>
#include <chrono>
#include <cstdint>
#include <immintrin.h> // SIMD可选

using namespace std;
using namespace chrono;

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

// -------------------- 基础版 --------------------
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

void SM3_basic(const uint8_t* message, size_t len, uint8_t hash[32]) {
    vector<uint8_t> m = padding(message, len);
    uint32_t V[8]; memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < m.size(); i += 64) CF_basic(V, &m[i]);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = V[i] >> 24; hash[i * 4 + 1] = V[i] >> 16;
        hash[i * 4 + 2] = V[i] >> 8; hash[i * 4 + 3] = V[i];
    }
}

// -------------------- T-table 优化版 --------------------
uint32_t T_P0[0x10000], T_P1[0x10000];
void init_Ttable() {
    for (uint32_t i = 0; i < 0x10000; i++) {
        T_P0[i] = P0(i);
        T_P1[i] = P1(i);
    }
}
uint32_t P0_table(uint32_t x) { return T_P0[x & 0xFFFF]; }
uint32_t P1_table(uint32_t x) { return T_P1[x & 0xFFFF]; }

void CF_Ttable(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    for (int i = 0; i < 16; i++)
        W[i] = (B[i * 4] << 24) | (B[i * 4 + 1] << 16) | (B[i * 4 + 2] << 8) | B[i * 4 + 3];
    for (int i = 16; i < 68; i++)
        W[i] = P1_table(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B1 = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj[j], j)) & 0xFFFFFFFF, 7);
        uint32_t SS2 = SS1 ^ ROTL(A, 12);
        uint32_t TT1 = (FF(A, B1, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
        uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
        D = C; C = ROTL(B1, 9); B1 = A; A = TT1;
        H = G; G = ROTL(F, 19); F = E; E = P0_table(TT2);
    }
    for (int i = 0; i < 8; i++) V[i] ^= (i == 0 ? A : i == 1 ? B1 : i == 2 ? C : i == 3 ? D : i == 4 ? E : i == 5 ? F : i == 6 ? G : H);
}

void SM3_Ttable(const uint8_t* message, size_t len, uint8_t hash[32]) {
    vector<uint8_t> m = padding(message, len);
    uint32_t V[8]; memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < m.size(); i += 64) CF_Ttable(V, &m[i]);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = V[i] >> 24; hash[i * 4 + 1] = V[i] >> 16;
        hash[i * 4 + 2] = V[i] >> 8; hash[i * 4 + 3] = V[i];
    }
}

// -------------------- 高级优化版 --------------------
void CF_advanced(uint32_t V[8], const uint8_t B[64]) {
    uint32_t W[68], W1[64];
    const uint32_t* B32 = (const uint32_t*)B;
    for (int i = 0; i < 16; i++) W[i] = _byteswap_ulong(B32[i]);
    for (int i = 16; i < 68; i++)
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL(W[i - 3], 15)) ^ ROTL(W[i - 13], 7) ^ W[i - 6];
    for (int i = 0; i < 64; i++) W1[i] = W[i] ^ W[i + 4];

    uint32_t A = V[0], B1 = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
    for (int j = 0; j < 64; j += 4) {
        for (int k = 0; k < 4; k++) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj[j + k], j + k)) & 0xFFFFFFFF, 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = (FF(A, B1, C, j + k) + D + SS2 + W1[j + k]) & 0xFFFFFFFF;
            uint32_t TT2 = (GG(E, F, G, j + k) + H + SS1 + W[j + k]) & 0xFFFFFFFF;
            D = C; C = ROTL(B1, 9); B1 = A; A = TT1;
            H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
        }
    }
    for (int i = 0; i < 8; i++) V[i] ^= (i == 0 ? A : i == 1 ? B1 : i == 2 ? C : i == 3 ? D : i == 4 ? E : i == 5 ? F : i == 6 ? G : H);
}

void SM3_advanced(const uint8_t* message, size_t len, uint8_t hash[32]) {
    vector<uint8_t> m = padding(message, len);
    uint32_t V[8]; memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < m.size(); i += 64) CF_advanced(V, &m[i]);
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = V[i] >> 24; hash[i * 4 + 1] = V[i] >> 16;
        hash[i * 4 + 2] = V[i] >> 8; hash[i * 4 + 3] = V[i];
    }
}

// -------------------- SIMD 思路版 --------------------
void SM3_SIMD(const uint8_t* message, size_t len, uint8_t hash[32]) {
    vector<uint8_t> m = padding(message, len);
    uint32_t V[8]; memcpy(V, IV, sizeof(IV));
    for (size_t i = 0; i < m.size(); i += 64) {
        uint32_t W[68], W1[64];
        const uint32_t* B32 = (const uint32_t*)&m[i];
        for (int j = 0; j < 16; j++) W[j] = _byteswap_ulong(B32[j]);
        for (int j = 16; j < 68; j++)
            W[j] = P1(W[j - 16] ^ W[j - 9] ^ ROTL(W[j - 3], 15)) ^ ROTL(W[j - 13], 7) ^ W[j - 6];
        for (int j = 0; j < 64; j++) W1[j] = W[j] ^ W[j + 4];

        uint32_t A = V[0], B1 = V[1], C = V[2], D = V[3], E = V[4], F = V[5], G = V[6], H = V[7];
        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL((ROTL(A, 12) + E + ROTL(Tj[j], j)) & 0xFFFFFFFF, 7);
            uint32_t SS2 = SS1 ^ ROTL(A, 12);
            uint32_t TT1 = (FF(A, B1, C, j) + D + SS2 + W1[j]) & 0xFFFFFFFF;
            uint32_t TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xFFFFFFFF;
            D = C; C = ROTL(B1, 9); B1 = A; A = TT1;
            H = G; G = ROTL(F, 19); F = E; E = P0(TT2);
        }
        for (int j = 0; j < 8; j++) V[j] ^= (j == 0 ? A : j == 1 ? B1 : j == 2 ? C : j == 3 ? D : j == 4 ? E : j == 5 ? F : j == 6 ? G : H);
    }
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = V[i] >> 24; hash[i * 4 + 1] = V[i] >> 16;
        hash[i * 4 + 2] = V[i] >> 8; hash[i * 4 + 3] = V[i];
    }
}

// -------------------- 测试函数 --------------------
void test_version(const string& name, void(*sm3_func)(const uint8_t*, size_t, uint8_t*), const uint8_t* msg, size_t len) {
    uint8_t hash[32];
    auto start = high_resolution_clock::now();
    sm3_func(msg, len, hash);
    auto end = high_resolution_clock::now();

    cout << name << " Hash: ";
    for (int i = 0; i < 32; i++) cout << hex << setw(2) << setfill('0') << (int)hash[i];
    cout << endl;
    cout << name << " Time: " << duration_cast<nanoseconds>(end - start).count() << " ns" << endl;
    cout << "-------------------------------" << endl;
}

// -------------------- 主函数 --------------------
int main() {
    const char* test = "abc";
    init_Ttable(); // 初始化T-table
    cout << "SM3 多版本对比实验\n";
    cout << "===============================\n";
    test_version("Basic", SM3_basic, (const uint8_t*)test, strlen(test));
    test_version("T-table", SM3_Ttable, (const uint8_t*)test, strlen(test));
    test_version("Advanced", SM3_advanced, (const uint8_t*)test, strlen(test));
    test_version("SIMD", SM3_SIMD, (const uint8_t*)test, strlen(test));
    return 0;
}
