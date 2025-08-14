pragma circom 2.0.0;

include "circomlib/poseidon.circom"; // 引入 circomlib 的 Poseidon 组件

template Poseidon2Circuit() {
    // 私有输入
    signal input x[1];  // 单 block 输入
    // 公共输出
    signal input h;     // Poseidon2 哈希值

    // 使用 circomlib Poseidon
    component poseidonHasher = Poseidon(3);
    poseidonHasher.inputs[0] <== x[0];
    poseidonHasher.inputs[1] <== 0;
    poseidonHasher.inputs[2] <== 0;

    // 输出约束
    h === poseidonHasher.out;
}

component main = Poseidon2Circuit();
