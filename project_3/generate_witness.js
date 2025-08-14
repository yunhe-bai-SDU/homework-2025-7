const fs = require("fs");
const wasm_tester = require("circom_tester").wasm;

async function main() {
    // 加载电路
    const circuit = await wasm_tester("poseidon2.circom");

    // 读取输入
    const input = JSON.parse(fs.readFileSync("input.json"));

    // 计算 witness
    const witness = await circuit.calculateWitness(input, true);

    // 输出 witness 到文件
    fs.writeFileSync("witness.wtns", JSON.stringify(witness, null, 2));
    console.log("Witness 已生成: witness.wtns");
}

main();
