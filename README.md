# 网络空间安全创新创业实践

**姓名**：白耘赫  
**学号**：202200460018  
**班级**：22级网安2班  
**实验方式**：独立完成  

---

## 实验内容

### Project 1: SM4 软件实现与优化
- **目标**：从基本实现出发优化 SM4 软件执行效率
- **要求**：
  1. 优化方法至少覆盖 T-table、AESNI 以及最新指令集（GFNI、VPROLD 等）
  2. 基于 SM4 实现，完成 SM4-GCM 工作模式的软件优化实现

---

### Project 2: 基于数字水印的图片泄露检测
- **目标**：实现图片水印嵌入与提取，并进行鲁棒性测试
- **任务**：
  1. 编程实现图片水印嵌入和提取（可依托开源项目二次开发）
  2. 鲁棒性测试，包括但不限于翻转、平移、截取、调节对比度等

---

### Project 3: 用 Circom 实现 Poseidon2 哈希算法电路
- **目标**：实现 Poseidon2 哈希算法电路并生成证明
- **任务**：
  1. 哈希算法参数参考文档 1 的 Table 1，使用 `(n,t,d)=(256,3,5)` 或 `(256,2,5)`
  2. 电路输入：
     - 公开输入：Poseidon2 哈希值
     - 隐私输入：哈希原象
     - 输入仅考虑一个 block
  3. 使用 Groth16 算法生成证明
- **参考文档**：
  1. Poseidon2 哈希算法：[https://eprint.iacr.org/2023/323.pdf](https://eprint.iacr.org/2023/323.pdf)
  2. Circom 官方文档：[https://docs.circom.io/](https://docs.circom.io/)
  3. Circom 电路样例：[https://github.com/iden3/circomlib](https://github.com/iden3/circomlib)

---

### Project 4: SM3 软件实现与优化
- **目标**：优化 SM3 软件实现，并进行安全性验证
- **任务**：
  1. 从基本软件实现出发，参考付勇老师的 PPT，对 SM3 执行效率进行优化
  2. 基于 SM3 实现，验证 **length-extension attack**
  3. 基于 SM3 实现，依据 RFC6962 构建 Merkle 树（10 万叶子节点），并生成叶子的存在性证明与不存在性证明

---

### Project 5: SM2 软件实现与优化
- **目标**：优化 SM2 软件实现并验证签名算法的安全性
- **任务**：
  1. 使用 Python 实现 SM2 基础算法及改进尝试（C 语言实现较复杂）
  2. 根据 `20250713-wen-sm2-public.pdf` 中关于签名算法误用的内容，完成 PoC 验证，提供推导文档与验证代码
  3. 尝试伪造中本聪的数字签名

---

### Project 6: Google Password Checkup 验证
- **目标**：实现 Google Password Checkup 协议
- **任务**：
  1. 参考刘巍然老师报告及论文 [https://eprint.iacr.org/2019/723.pdf](https://eprint.iacr.org/2019/723.pdf) 的 Section 3.1，即 Figure 2 展示的协议
  2. 尝试实现该协议
