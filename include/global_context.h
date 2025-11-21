#pragma once
#include <openssl/sha.h>
#include <mcl/bls12_381.hpp>
#include <vector>
#include <iostream>
// #ifndef BBS_ELL
// #define BBS_ELL 1  
// #endif

extern "C" {
    #include "../src/ecvrf_p256.c" 
}

// ===========================================================
// GlobalContext: 全局 BLS12-381 环境 + 公共参数 (G1, G2, H-vector)
// ===========================================================
namespace GlobalContext {

struct Environment {
    bool initialized = false;

    // === 椭圆曲线基点 ===
    mcl::bn::G1 G1_;
    mcl::bn::G2 G2_;

    // === BBS+ 基向量 H0..H_ell ===
    std::vector<mcl::bn::G1> bbs_H;
    static constexpr size_t bbs_ell = 1; 

    // 初始化 pairing + 公共参数
    void init() {
        if (initialized) return;
        initialized = true;

        // std::cout << "[GlobalContext] Initializing BLS12-381 pairing...\n";
        mcl::bn::initPairing(mcl::BLS12_381);

        // 1. 初始化 G1, G2 基点
        mcl::bn::hashAndMapToG1(G1_, "1");
        mcl::bn::hashAndMapToG2(G2_, "2");

        // 2. 初始化 BBS+ 基向量 H_i
        bbs_H.resize(bbs_ell + 1);
        for (size_t i = 0; i <= bbs_ell; ++i) {
            mcl::bn::Fr tmp;
            tmp.setByCSPRNG();
            mcl::bn::G1::mul(bbs_H[i], G1_, tmp);
        }

        // std::cout << "[GlobalContext] G1/G2 and "
        //           << bbs_ell + 1 << " BBS+ base points vector initialized.\n";
    }

    // === 哈希到 Fr，用于挑战生成 ===
    static mcl::bn::Fr hashToFr(const std::string &input) {
        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256_CTX ctx;
        SHA256_Init(&ctx);
        SHA256_Update(&ctx, input.data(), input.size());
        SHA256_Final(hash, &ctx);

        mcl::bn::Fr out;
        out.setArrayMask(hash, sizeof(hash)); // 取模群阶
        return out;
    }
};

// === 单例 ===
inline Environment &ctx() {
    static Environment env;
    return env;
}

// === 对外接口 ===
inline void init() { ctx().init(); }

// 快捷访问全局参数
inline const mcl::bn::G1& G1() { return ctx().G1_; }
inline const mcl::bn::G2& G2() { return ctx().G2_; }
inline const std::vector<mcl::bn::G1>& H() { return ctx().bbs_H; }

} // namespace GlobalContext
