#include <iostream>
#include <vector>
#include <string>
#include <map>
#include <algorithm>
#include <iomanip>
#include <cstdint>
#include <random>

using namespace std;

// ------------------- SM3 哈希函数占位 -------------------
// 这里假设你有一个 SM3 实现
// 将输入 vector<uint8_t> 返回 32 字节哈希
vector<uint8_t> hashSM3(const vector<uint8_t>& data) {
    // 简化示例：这里用 std::hash 模拟 SM3 输出
    // 实际使用时替换为真实 SM3 实现
    vector<uint8_t> hash(32, 0);
    size_t h = std::hash<string>{}(string(data.begin(), data.end()));
    for (int i = 0; i < 32; i++) {
        hash[i] = (h >> (i * 2)) & 0xFF;
    }
    return hash;
}

// ------------------- Merkle 树节点 -------------------
struct MerkleNode {
    vector<uint8_t> hash;
    MerkleNode* left = nullptr;
    MerkleNode* right = nullptr;
    bool is_leaf = false;
    int index = -1; // 叶子索引
};

// ------------------- Merkle 树 -------------------
class MerkleTree {
public:
    MerkleTree(const vector<string>& leaves_data);
    vector<uint8_t> rootHash();
    vector<vector<uint8_t>> getInclusionProof(int leaf_index);
    pair<vector<uint8_t>, vector<vector<uint8_t>>> getNonInclusionProof(const string& value);

private:
    MerkleNode* buildTree(const vector<MerkleNode*>& nodes);
    MerkleNode* findParent(MerkleNode* current, MerkleNode* child);
    vector<MerkleNode*> leaves;
    MerkleNode* root = nullptr;
    map<string, int> leaf_map; // 方便查找叶子索引
};

// ------------------- 构造函数 -------------------
MerkleTree::MerkleTree(const vector<string>& leaves_data) {
    for (int i = 0; i < leaves_data.size(); i++) {
        vector<uint8_t> leaf_bytes(leaves_data[i].begin(), leaves_data[i].end());
        vector<uint8_t> input = { 0x00 };
        input.insert(input.end(), leaf_bytes.begin(), leaf_bytes.end());
        vector<uint8_t> h = hashSM3(input);
        MerkleNode* node = new MerkleNode{ h,nullptr,nullptr,true,i };
        leaves.push_back(node);
        leaf_map[leaves_data[i]] = i;
    }
    root = buildTree(leaves);
}

// ------------------- 构建树 -------------------
MerkleNode* MerkleTree::buildTree(const vector<MerkleNode*>& nodes) {
    if (nodes.size() == 1) return nodes[0];
    vector<MerkleNode*> parents;
    for (size_t i = 0; i < nodes.size(); i += 2) {
        MerkleNode* left = nodes[i];
        MerkleNode* right = (i + 1 < nodes.size()) ? nodes[i + 1] : nullptr;
        vector<uint8_t> combined = { 0x01 };
        combined.insert(combined.end(), left->hash.begin(), left->hash.end());
        if (right) combined.insert(combined.end(), right->hash.begin(), right->hash.end());
        vector<uint8_t> h = hashSM3(combined);
        MerkleNode* parent = new MerkleNode{ h,left,right,false,-1 };
        parents.push_back(parent);
    }
    return buildTree(parents);
}

// ------------------- 根哈希 -------------------
vector<uint8_t> MerkleTree::rootHash() {
    return root->hash;
}

// ------------------- 查找父节点 -------------------
MerkleNode* MerkleTree::findParent(MerkleNode* current, MerkleNode* child) {
    if (!current || current->is_leaf) return nullptr;
    if (current->left == child || current->right == child) return current;
    MerkleNode* p = findParent(current->left, child);
    if (p) return p;
    return findParent(current->right, child);
}

// ------------------- 存在性证明 -------------------
vector<vector<uint8_t>> MerkleTree::getInclusionProof(int leaf_index) {
    vector<vector<uint8_t>> path;
    MerkleNode* node = leaves[leaf_index];
    while (node != root) {
        MerkleNode* parent = findParent(root, node);
        MerkleNode* sibling = (parent->left == node) ? parent->right : parent->left;
        if (sibling) path.push_back(sibling->hash);
        node = parent;
    }
    return path;
}

// ------------------- 不存在性证明 -------------------
pair<vector<uint8_t>, vector<vector<uint8_t>>> MerkleTree::getNonInclusionProof(const string& value) {
    auto it = leaf_map.lower_bound(value);
    if (it == leaf_map.end()) --it;
    int leaf_index = it->second;
    return { leaves[leaf_index]->hash,getInclusionProof(leaf_index) };
}

// ------------------- 打印哈希 -------------------
void printHash(const vector<uint8_t>& h) {
    for (auto b : h) cout << hex << setw(2) << setfill('0') << (int)b;
    cout << endl;
}

// ------------------- 主函数 -------------------
int main() {
    const int N = 100000; // 10万叶子
    vector<string> leaves;
    for (int i = 0; i < N; i++) {
        leaves.push_back("leaf_" + to_string(i));
    }

    cout << "Building Merkle Tree..." << endl;
    MerkleTree tree(leaves);
    cout << "Merkle Root: ";
    printHash(tree.rootHash());

    // 存在性证明
    int test_index = 12345;
    auto proof = tree.getInclusionProof(test_index);
    cout << "Existence Proof for " << leaves[test_index] << ":\n";
    for (size_t i = 0; i < proof.size(); i++) {
        cout << i + 1 << ". ";
        printHash(proof[i]);
    }

    // 不存在性证明
    string non_exist = "leaf_999999";
    auto non_proof = tree.getNonInclusionProof(non_exist);
    cout << "Non-Existence Proof for " << non_exist << ":\n";
    cout << "Closest existing leaf hash: ";
    printHash(non_proof.first);
    cout << "Inclusion proof for closest leaf:\n";
    for (size_t i = 0; i < non_proof.second.size(); i++) {
        cout << i + 1 << ". ";
        printHash(non_proof.second[i]);
    }

    return 0;
}
