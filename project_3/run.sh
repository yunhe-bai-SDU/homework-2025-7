#!/bin/bash

# 编译电路
circom poseidon2.circom --r1cs --wasm --sym

# 生成 Groth16 proving key
snarkjs groth16 setup poseidon2.r1cs pot12_final.ptau poseidon2_0000.zkey

# 贡献随机性（可选）
snarkjs zkey contribute poseidon2_0000.zkey poseidon2_final.zkey --name="Contributor 1"

# 导出验证键
snarkjs zkey export verificationkey poseidon2_final.zkey verification_key.json

# 生成 witness
node poseidon2_js/generate_witness.js poseidon2_js/poseidon2.wasm input.json witness.wtns

# 生成 proof
snarkjs groth16 prove poseidon2_final.zkey witness.wtns proof.json public.json

# 验证 proof
snarkjs groth16 verify verification_key.json public.json proof.json
