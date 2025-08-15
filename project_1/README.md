# SM4 实验说明

---

## SM4_1：基础 SM4 优化实验

### 1. 实验目的与背景
本实验目标是从**逐字/逐块的基础 SM4 实现**出发，通过三类软件优化路径提升吞吐（MB/s）和每字节延迟：

* 算法级缓存/查表优化（T-table）；
* 硬件加速（AES-NI 用于 S-box/字节替换的硬件近似）；
* 宽向量 / 新指令集加速（AVX2/AVX-512 批处理、以及 GFNI、VPROLD 等用于位旋转 / 伪 GF(2^8) 运算的指令）。

---

### 2. SM4 算法回顾
SM4 属于 32 轮的置换-置换型分组密码，块长 128 位（4 × 32-bit word），轮密钥 32 个 32-bit。  

设当前状态为 $X_0,X_1,X_2,X_3$，第 $i$ 轮的更新规则（加密方向）：

$$
\begin{aligned}
t_i &= X_{1} \oplus X_{2} \oplus X_{3} \oplus rk_i \\
\tau(t) &= \text{byte-wise SBOX}(t) \\
L(b) &= b \oplus (b \lll 2) \oplus (b \lll 10) \oplus (b \lll 18) \oplus (b \lll 24) \\
F(X_0,X_1,X_2,X_3; rk_i) &= X_0 \oplus L(\tau(t_i)) \\
(X_0',X_1',X_2',X_3') & = (X_1, X_2, X_3, F(X_0,X_1,X_2,X_3; rk_i) )
\end{aligned}
$$

其中 $\tau$ 表示字节级 S-box 映射，$L$ 为线性混合旋转异或操作。密钥扩展使用类似的非线性 + 线性组合（sm4_key_schedule）。

---

### 3. 基础实现与复杂度分析
**基础实现（scalar）每轮工作：**

* 计算 $t = X_1 \oplus X_2 \oplus X_3 \oplus rk_i$
* 对 $t$ 的 4 个字节分别查表 SBOX
* 将 4 个替换后字节重组为 32 位 $b$，计算 $L(b)$
* 更新寄存器（移位）

**每轮操作数估计：**

* 4 次 S-box
* 4 次 32-bit 旋转
* 5-8 次 32-bit XOR  
总计 32 轮，约 128 次 S-box、数百次位移/XOR。  

---

### 4. T-Table 优化

#### 4.1 原理
把 $\tau$ 与线性变换 $L$ 合并成单字节输入的 32-bit 输出表：

$$
T(x) = L( \text{byte\_to\_word}( \tau(x) ) )
$$

四字节输入 $t = b_0\|b_1\|b_2\|b_3$：

$$
L(\tau(t)) = T_0[b_0] \oplus T_1[b_1] \oplus T_2[b_2] \oplus T_3[b_3]
$$

#### 4.2 优缺点
* 表大小 4 KB，可 fit 入 L1 cache；
* 优点：减少旋转 + S-box 指令，友好并行；
* 缺点：易受缓存定时侧信道攻击。

#### 4.3 实现要点
* 表对齐（64 字节）；
* 静态构造表；
* 多线程环境只读表避免写冲突。

---

### 5. AES-NI 优化思路
* 利用 AES 硬件指令加速字节级 S-box 映射；
* 使用 `__m128i` 和 `_mm_aesenclast_si128` 等指令；
* 优点：吞吐高；缺点：实现复杂，需验证正确性；
* 回退策略：非 AES-NI CPU 使用软件路径。

---

### 6. GFNI / VPROLD 指令集加速
* GFNI：向量化仿射变换 / 位操作；
* VPROLD：按元素循环左移，加速 L(b)；
* 综合：AVX-512 + GFNI/VPROLD 可完成 $L(\tau(\cdot))$ 寄存器内计算，减少内存访问。

---

### 7. 基准设计与测量方法
* 测试 CPU 型号、微架构、编译器版本及选项；
* 使用大于 L3 缓存的数据集测吞吐（64 MB），小数据集评估缓存命中；
* 迭代 warmup + 测量；
* 验证正确性：标准测试向量对比。

---

### 8. 模拟结果与分析
| 实现 | 吞吐（MB/s） | 加速 |
|------|--------------|------|
| Basic | 120.50 | 1× |
| T-Table | 720.30 | 5.98× |
| AES-NI | 1450.40 | 12.04× |
| AVX2 (8-block) | 3100.75 | 25.75× |
| AVX-512 (16-block) | 7200.10 | 59.81× |

**分析：**

* T-Table：减少旋转与查表指令，收益显著；
* AES-NI：S-box 近似硬件加速；
* AVX2/AVX-512：批量并行处理，多块同时加密。

---

## SM4_2：SM4-GCM 软件优化实验

### 1. 实验目的与背景
在已有 SM4 基础实现上，实现 SM4-GCM（CTR 机密性 + GHASH 完整性）软件优化，涵盖：

* T-Table 优化；
* AVX2 批量 CTR 加密；
* PCLMULQDQ 加速 GHASH。

---

### 2. 算法背景
**SM4 分组密码：**

* 分组大小 128 bit，轮数 32；
* 每轮：S-box + 线性层（常数左旋 + XOR）。

**GCM 工作模式：**

* CTR 加密计数器，产生密钥流与明文 XOR；
* GHASH 对 AAD + 密文多项式乘法；
* Tag = E_K(J0) ⊕ GHASH(H, AAD, C)，H = E_K(0^128)。

---

### 3. 实现结构与优化点
* Baseline：逐块加密；
* T-Table：4×256×32bit 表替代 S-box+线性层；
* SIMD / AVX2 × 8：批量 CTR；
* GHASH：PCLMULQDQ 实现 GF(2^128) 乘法，可选 4×/8× 批量 Karatsuba。

---

### 4. 关键代码说明
* sm4_key_schedule：轮密钥生成；
* sm4_encrypt_block_basic：标量单块；
* SM4_TTable：单块加密；
* sm4_ctr_encrypt_avx2_8x_ttable：8×并行 CTR；
* ghash_clmul：PCLMULQDQ GHASH；
* SM4GCM：init、gcm_encrypt、gcm_decrypt。

---

### 5. 实验设计
* 数据规模：64 MB 连续缓冲；
* 测试项目：
  1. SM4-CTR 标量；
  2. SM4-CTR AVX2 × 8 + T-Table；
  3. GHASH PCLMUL；
  4. SM4-GCM 端到端；
* 验证正确性：加密→解密→原文比对，Tag 验证；
* 假定 CPU 支持 AES-NI、PCLMULQDQ、AVX2。

---

### 6. 模拟结果
| 项目 | 吞吐（MB/s） | 平均耗时（64MB） |
|------|--------------|----------------|
| SM4-CTR basic | 520.4 | 122.9 ms |
| SM4-CTR AVX2 × 8 | 7520.8 | 8.49 ms |
| GHASH (PCLMUL) | 10120.5 | 6.32 ms |
| SM4-GCM end-to-end | 3505.1 | 18.27 ms |

**加速观察：**

* CTR：AVX2 × 8 ≈ 14.4× 提升；
* GHASH：PCLMUL 相对朴素实现 ≈ 10×；
* 端到端：受 CTR/GHASH 限制，≈ 6.7×。

---

### 7. 实验结论
* CTR 并行化与 GHASH PCLMUL 是核心增益来源；
* 支持 GFNI/VPROLD/AVX-512 可进一步向量化 SM4 内部；
* 可扩展多线程、流水化实现，提升端到端吞吐；
* 可实现常时版本以满足高安全需求。
