#include <iostream>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <vector>
#include <intrin.h>  // Windows intrinsics header
#include <functional>

// 启用所有支持的指令集
#define ENABLE_BASIC 1
#define ENABLE_TTABLE 1
#define ENABLE_AESNI 1
#define ENABLE_AVX2 1
#define ENABLE_AVX512 1

// 检测编译器支持的指令集
#if defined(_MSC_VER)
#if defined(__AVX2__)
#define USE_AVX2 1
#endif
#if defined(__AVX512F__) && defined(__AVX512BW__)
#define USE_AVX512 1
#endif
#if defined(__AES__)
#define USE_AESNI 1
#endif
#endif

// SM4常量定义
const uint8_t SBOX[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};

const uint32_t FK[4] = { 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC };
const uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

// 工具函数
inline uint32_t rotl(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

inline uint32_t load_u32_be(const uint8_t* b) {
    return ((uint32_t)b[0] << 24) |
        ((uint32_t)b[1] << 16) |
        ((uint32_t)b[2] << 8) |
        (uint32_t)b[3];
}

inline void store_u32_be(uint32_t v, uint8_t* b) {
    b[0] = (uint8_t)(v >> 24);
    b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >> 8);
    b[3] = (uint8_t)v;
}

// 密钥扩展函数 (所有版本通用)
void sm4_key_schedule(const uint8_t key[16], uint32_t rk[32]) {
    uint32_t k[4];

    // 加载初始密钥
    k[0] = load_u32_be(key) ^ FK[0];
    k[1] = load_u32_be(key + 4) ^ FK[1];
    k[2] = load_u32_be(key + 8) ^ FK[2];
    k[3] = load_u32_be(key + 12) ^ FK[3];

    // 轮函数
    auto T = [](uint32_t x) -> uint32_t {
        uint32_t b = SBOX[x >> 24] << 24 |
            SBOX[(x >> 16) & 0xFF] << 16 |
            SBOX[(x >> 8) & 0xFF] << 8 |
            SBOX[x & 0xFF];
        return b ^ rotl(b, 13) ^ rotl(b, 23);
        };

    for (int i = 0; i < 32; i++) {
        k[i % 4] = k[(i + 1) % 4] ^
            k[(i + 2) % 4] ^
            k[(i + 3) % 4] ^
            T(k[(i + 1) % 4] ^ k[(i + 2) % 4] ^ k[(i + 3) % 4] ^ CK[i]);
        rk[i] = k[i % 4];
    }
}

// ====================== 1. 基础实现 ======================
#if ENABLE_BASIC
void sm4_encrypt_block_basic(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    uint32_t x[4];

    // 加载输入
    x[0] = load_u32_be(in);
    x[1] = load_u32_be(in + 4);
    x[2] = load_u32_be(in + 8);
    x[3] = load_u32_be(in + 12);

    // 轮函数
    auto F = [&](uint32_t r) -> uint32_t {
        uint32_t t = x[1] ^ x[2] ^ x[3] ^ rk[r];
        t = SBOX[t >> 24] << 24 |
            SBOX[(t >> 16) & 0xFF] << 16 |
            SBOX[(t >> 8) & 0xFF] << 8 |
            SBOX[t & 0xFF];
        return x[0] ^ t ^ rotl(t, 2) ^ rotl(t, 10) ^ rotl(t, 18) ^ rotl(t, 24);
        };

    // 32轮加密
    for (int i = 0; i < 32; i++) {
        uint32_t tmp = F(i);
        x[0] = x[1];
        x[1] = x[2];
        x[2] = x[3];
        x[3] = tmp;
    }

    // 存储结果
    store_u32_be(x[3], out);
    store_u32_be(x[2], out + 4);
    store_u32_be(x[1], out + 8);
    store_u32_be(x[0], out + 12);
}
#endif

// ====================== 2. T-Table优化 ======================
#if ENABLE_TTABLE
class SM4_TTable {
public:
    SM4_TTable() {
        for (int i = 0; i < 256; i++) {
            uint32_t a = SBOX[i];
            uint32_t b = a ^ rotl(a, 2) ^ rotl(a, 10) ^ rotl(a, 18) ^ rotl(a, 24);
            T0[i] = b;
            T1[i] = rotl(b, 24);
            T2[i] = rotl(b, 16);
            T3[i] = rotl(b, 8);
        }
    }

    void encrypt_block(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
        uint32_t x[4];

        // 加载输入
        x[0] = load_u32_be(in);
        x[1] = load_u32_be(in + 4);
        x[2] = load_u32_be(in + 8);
        x[3] = load_u32_be(in + 12);

        for (int i = 0; i < 32; i++) {
            uint32_t t = x[1] ^ x[2] ^ x[3] ^ rk[i];
            uint32_t tmp = T0[t >> 24] ^
                T1[(t >> 16) & 0xFF] ^
                T2[(t >> 8) & 0xFF] ^
                T3[t & 0xFF];
            tmp ^= x[0];

            x[0] = x[1];
            x[1] = x[2];
            x[2] = x[3];
            x[3] = tmp;
        }

        // 存储结果
        store_u32_be(x[3], out);
        store_u32_be(x[2], out + 4);
        store_u32_be(x[1], out + 8);
        store_u32_be(x[0], out + 12);
    }

private:
    uint32_t T0[256], T1[256], T2[256], T3[256];
};
#endif

// ====================== 3. AES-NI优化 ======================
#if ENABLE_AESNI && USE_AESNI
__m128i sm4_sbox_aesni(__m128i x) {
    const __m128i zero = _mm_setzero_si128();
    x = _mm_aesenclast_si128(x, zero);
    x = _mm_aesimc_si128(x);
    x = _mm_aesenclast_si128(x, zero);
    return _mm_shuffle_epi8(x, _mm_setr_epi8(
        13, 2, 9, 14, 1, 4, 11, 8, 3, 15, 6, 12, 5, 10, 7, 0
    ));
}

void sm4_encrypt_block_aesni(const uint32_t rk[32], const uint8_t in[16], uint8_t out[16]) {
    __m128i state = _mm_loadu_si128((const __m128i*)in);
    state = _mm_shuffle_epi8(state, _mm_setr_epi8(
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    ));

    for (int i = 0; i < 32; i++) {
        // 轮密钥加
        __m128i round_key = _mm_set1_epi32(rk[i]);
        state = _mm_xor_si128(state, round_key);

        // S盒变换
        state = sm4_sbox_aesni(state);

        // 线性变换
        __m128i t0 = _mm_slli_epi32(state, 2);
        __m128i t1 = _mm_slli_epi32(state, 10);
        __m128i t2 = _mm_slli_epi32(state, 18);
        __m128i t3 = _mm_slli_epi32(state, 24);
        state = _mm_xor_si128(state, t0);
        state = _mm_xor_si128(state, t1);
        state = _mm_xor_si128(state, t2);
        state = _mm_xor_si128(state, t3);

        // 移位寄存器
        state = _mm_shuffle_epi32(state, _MM_SHUFFLE(2, 1, 0, 3));
    }

    // 最终置换
    state = _mm_shuffle_epi32(state, _MM_SHUFFLE(0, 1, 2, 3));
    state = _mm_shuffle_epi8(state, _mm_setr_epi8(
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    ));
    _mm_storeu_si128((__m128i*)out, state);
}
#endif

// ====================== 4. AVX2+GFNI优化 ======================
#if ENABLE_AVX2 && USE_AVX2
__m256i sm4_linear_avx2(__m256i x) {
    __m256i t0 = _mm256_slli_epi32(x, 2);
    __m256i t1 = _mm256_slli_epi32(x, 10);
    __m256i t2 = _mm256_slli_epi32(x, 18);
    __m256i t3 = _mm256_slli_epi32(x, 24);
    x = _mm256_xor_si256(x, t0);
    x = _mm256_xor_si256(x, t1);
    x = _mm256_xor_si256(x, t2);
    return _mm256_xor_si256(x, t3);
}

void sm4_encrypt_8blocks_avx2(const uint32_t rk[32], const uint8_t* in, uint8_t* out) {
    __m256i state0 = _mm256_loadu_si256((const __m256i*)(in));
    __m256i state1 = _mm256_loadu_si256((const __m256i*)(in + 32));

    // 字节序调整
    const __m256i bswap = _mm256_setr_epi8(
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    );
    state0 = _mm256_shuffle_epi8(state0, bswap);
    state1 = _mm256_shuffle_epi8(state1, bswap);

    for (int i = 0; i < 32; i++) {
        __m256i round_key = _mm256_set1_epi32(rk[i]);

        // 轮密钥加
        state0 = _mm256_xor_si256(state0, round_key);
        state1 = _mm256_xor_si256(state1, round_key);

        // S盒变换 (使用查表法代替GFNI)
        auto apply_sbox = [](__m256i x) -> __m256i {
            alignas(32) static const uint8_t sbox_table[256] = {
                0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
                // ... 完整S盒数据
            };
            alignas(32) uint8_t temp[32];
            _mm256_store_si256((__m256i*)temp, x);

            for (int j = 0; j < 32; j++) {
                temp[j] = sbox_table[temp[j]];
            }

            return _mm256_load_si256((__m256i*)temp);
        };

        state0 = apply_sbox(state0);
        state1 = apply_sbox(state1);

        // 线性变换
        state0 = sm4_linear_avx2(state0);
        state1 = sm4_linear_avx2(state1);

        // 移位寄存器
        state0 = _mm256_shuffle_epi32(state0, _MM_SHUFFLE(2, 1, 0, 3));
        state1 = _mm256_shuffle_epi32(state1, _MM_SHUFFLE(2, 1, 0, 3));
    }

    // 最终置换
    state0 = _mm256_shuffle_epi32(state0, _MM_SHUFFLE(0, 1, 2, 3));
    state1 = _mm256_shuffle_epi32(state1, _MM_SHUFFLE(0, 1, 2, 3));
    state0 = _mm256_shuffle_epi8(state0, bswap);
    state1 = _mm256_shuffle_epi8(state1, bswap);

    _mm256_storeu_si256((__m256i*)(out), state0);
    _mm256_storeu_si256((__m256i*)(out + 32), state1);
}
#endif

// ====================== 5. AVX-512优化 ======================
#if ENABLE_AVX512 && USE_AVX512
__m512i sm4_linear_avx512(__m512i x) {
    auto rol32 = [](__m512i v, int n) -> __m512i {
        return _mm512_or_si512(_mm512_slli_epi32(v, n),
            _mm512_srli_epi32(v, 32 - n));
        };

    x = _mm512_xor_epi32(x, rol32(x, 2));
    x = _mm512_xor_epi32(x, rol32(x, 10));
    x = _mm512_xor_epi32(x, rol32(x, 18));
    return _mm512_xor_epi32(x, rol32(x, 24));
}

void sm4_encrypt_16blocks_avx512(const uint32_t rk[32], const uint8_t* in, uint8_t* out) {
    __m512i state = _mm512_loadu_si512((const __m512i*)in);

    // 字节序调整
    const __m512i bswap = _mm512_setr_epi8(
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12,
        3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12
    );
    state = _mm512_shuffle_epi8(state, bswap);

    for (int i = 0; i < 32; i++) {
        __m512i round_key = _mm512_set1_epi32(rk[i]);

        // 轮密钥加
        state = _mm512_xor_epi32(state, round_key);

        // S盒变换 (使用查表法)
        auto apply_sbox = [](__m512i x) -> __m512i {
            alignas(64) static const uint8_t sbox_table[256] = {
                0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
                // ... 完整S盒数据
            };
            alignas(64) uint8_t temp[64];
            _mm512_store_si512((__m512i*)temp, x);

            for (int j = 0; j < 64; j++) {
                temp[j] = sbox_table[temp[j]];
            }

            return _mm512_load_si512((__m512i*)temp);
            };

        state = apply_sbox(state);

        // 线性变换
        state = sm4_linear_avx512(state);

        // 移位寄存器
        state = _mm512_shuffle_epi32(state, _MM_SHUFFLE(2, 1, 0, 3));
    }

    // 最终置换
    state = _mm512_shuffle_epi32(state, _MM_SHUFFLE(0, 1, 2, 3));
    state = _mm512_shuffle_epi8(state, bswap);
    _mm512_storeu_si512((__m512i*)out, state);
}
#endif

// ====================== 测试工具函数 ======================
void print_hex(const char* label, const uint8_t* data, size_t len) {
    std::cout << label << ": ";
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    }
    std::cout << std::dec << std::endl;
}

void test_correctness() {
    // SM4标准测试向量
    const uint8_t key[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    const uint8_t plaintext[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };

    const uint8_t expected[16] = {
        0x68, 0x1E, 0xDF, 0x34, 0xD2, 0x06, 0x96, 0x5E,
        0x86, 0xB3, 0xE9, 0x4F, 0x53, 0x6E, 0x42, 0x46
    };

    uint32_t rk[32];
    uint8_t ciphertext[64] = { 0 };  // 确保足够大

    // 生成轮密钥
    sm4_key_schedule(key, rk);

    std::cout << "SM4 Encryption Correctness Test:\n";

    // 测试基础实现
#if ENABLE_BASIC
    sm4_encrypt_block_basic(rk, plaintext, ciphertext);
    print_hex("Basic      ", ciphertext, 16);
#endif

    // 测试T-Table优化
#if ENABLE_TTABLE
    {
        SM4_TTable tt;
        tt.encrypt_block(rk, plaintext, ciphertext);
        print_hex("T-Table    ", ciphertext, 16);
    }
#endif

    // 测试AES-NI优化
#if ENABLE_AESNI && USE_AESNI
    sm4_encrypt_block_aesni(rk, plaintext, ciphertext);
    print_hex("AES-NI     ", ciphertext, 16);
#endif

    // 测试AVX2优化
#if ENABLE_AVX2 && USE_AVX2
    {
        uint8_t input8[64] = { 0 };
        uint8_t output8[64] = { 0 };
        memcpy(input8, plaintext, 16);
        sm4_encrypt_8blocks_avx2(rk, input8, output8);
        print_hex("AVX2       ", output8, 16);
    }
#endif

    // 测试AVX-512优化
#if ENABLE_AVX512 && USE_AVX512
    {
        uint8_t input16[256] = { 0 };
        uint8_t output16[256] = { 0 };
        memcpy(input16, plaintext, 16);
        sm4_encrypt_16blocks_avx512(rk, input16, output16);
        print_hex("AVX512     ", output16, 16);
    }
#endif

    std::cout << "Expected   : 681edf34d206965e86b3e94f536e4246\n\n";
}

  // 添加 functional 头文件

// ... [保留之前的常量定义和工具函数] ...

// ====================== 修改后的性能测试函数 ======================
// 使用 std::function 替代原始函数指针
void benchmark_impl(const char* name,
    std::function<void(const uint32_t*, const uint8_t*, uint8_t*)> func,
    size_t block_size,
    uint32_t rk[32],
    const uint8_t* data,
    uint8_t* output,
    size_t data_size,
    int iterations) {
    size_t blocks = data_size / block_size;
    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < iterations; i++) {
        for (size_t j = 0; j < blocks; j++) {
            func(rk, data + j * block_size, output + j * block_size);
        }
    }

    auto end = std::chrono::high_resolution_clock::now();

    // 修复 C4244 警告：添加显式类型转换
    double time_ms = static_cast<double>(
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count()
        );

    // 修复 C4244 警告：使用 double 类型避免精度损失
    double total_bytes = static_cast<double>(data_size) * iterations;
    double speed = total_bytes / (time_ms / 1000.0) / (1024 * 1024);  // MB/s

    std::cout << name << ": " << std::fixed << std::setprecision(2)
        << speed << " MB/s (" << time_ms / iterations << " ms per run)\n";
}

void benchmark() {
    const size_t MB = 1024 * 1024;
    const size_t data_size = 64 * MB;  // 64MB测试数据
    const int iterations = 10;         // 10次迭代

    // 使用_aligned_malloc确保内存对齐
    uint8_t* data = static_cast<uint8_t*>(_aligned_malloc(data_size, 64));
    uint8_t* output = static_cast<uint8_t*>(_aligned_malloc(data_size, 64));
    memset(data, 0xAA, data_size);  // 填充测试数据

    const uint8_t key[16] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
                            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    uint32_t rk[32];
    sm4_key_schedule(key, rk);

    std::cout << "Performance Benchmark (64MB data, 10 iterations):\n";

#if ENABLE_BASIC
    benchmark_impl("Basic      ",
        [](const uint32_t* rk, const uint8_t* in, uint8_t* out) {
            sm4_encrypt_block_basic(rk, in, out);
        },
        16, rk, data, output, data_size, iterations);
#endif

#if ENABLE_TTABLE
    {
        static SM4_TTable tt;  // 使用 static 避免捕获
        benchmark_impl("T-Table    ",
            [](const uint32_t* rk, const uint8_t* in, uint8_t* out) {
                tt.encrypt_block(rk, in, out);
            },
            16, rk, data, output, data_size, iterations);
    }
#endif

#if ENABLE_AESNI && USE_AESNI
    benchmark_impl("AES-NI     ",
        [](const uint32_t* rk, const uint8_t* in, uint8_t* out) {
            sm4_encrypt_block_aesni(rk, in, out);
        },
        16, rk, data, output, data_size, iterations);
#endif

#if ENABLE_AVX2 && USE_AVX2
    benchmark_impl("AVX2       ",
        [](const uint32_t* rk, const uint8_t* in, uint8_t* out) {
            sm4_encrypt_8blocks_avx2(rk, in, out);
        },
        64, rk, data, output, data_size, iterations);
#endif

#if ENABLE_AVX512 && USE_AVX512
    benchmark_impl("AVX512     ",
        [](const uint32_t* rk, const uint8_t* in, uint8_t* out) {
            sm4_encrypt_16blocks_avx512(rk, in, out);
        },
        256, rk, data, output, data_size, iterations);
#endif

    _aligned_free(data);
    _aligned_free(output);
}

// ... [保留其他函数不变] ...

// CPU特性检测
void print_cpu_features() {
    int cpuInfo[4];
    __cpuid(cpuInfo, 1);

    std::cout << "CPU Features:\n";
    std::cout << "SSE2:   " << ((cpuInfo[3] & (1 << 26)) ? "YES" : "NO") << "\n";
    std::cout << "AES:    " << ((cpuInfo[2] & (1 << 25)) ? "YES" : "NO") << "\n";
    std::cout << "AVX:    " << ((cpuInfo[2] & (1 << 28)) ? "YES" : "NO") << "\n";
    std::cout << "AVX2:   " << ((cpuInfo[7] & (1 << 5)) ? "YES" : "NO") << "\n";

    __cpuidex(cpuInfo, 7, 0);
    std::cout << "AVX512F: " << ((cpuInfo[1] & (1 << 16)) ? "YES" : "NO") << "\n";
    std::cout << "AVX512BW: " << ((cpuInfo[1] & (1 << 30)) ? "YES" : "NO") << "\n";
    std::cout << "GFNI:   " << ((cpuInfo[1] & (1 << 8)) ? "YES" : "NO") << "\n\n";
}

int main() {
    print_cpu_features();
    test_correctness();

#if (ENABLE_AESNI || ENABLE_AVX2 || ENABLE_AVX512)
    benchmark();
#else
    std::cout << "Benchmark skipped: Advanced instructions not enabled\n";
#endif

    return 0;
}