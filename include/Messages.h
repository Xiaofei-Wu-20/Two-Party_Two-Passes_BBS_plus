#pragma once
#include "global_context.h"
#include <vector>
#include <string>
#include <mcl/bls12_381.hpp>
#include "bicycl/bicycl.hpp"
#include "bicycl/CL_HSMqk.hpp"
#include "zk_sigma.h"


struct BBS_Plus_Signature {
    mcl::bn::G1 A;   // group element in G1
    mcl::bn::Fr e;   // scalar
    mcl::bn::Fr s;   // scalar
};

// ========== Round 1：P1 -> P2 ==========
struct MsgCommit_P1toP2 {
    std::vector<uint8_t> com1;
};

// ========== Round 2：P2 -> P1 ==========
struct MsgBundle_P2toP1 {
    mcl::bn::G2 X2;
    ZK::RDL_Proof pi2_DL;
    EC_POINT* vrf_pub;
};

// ========== Round 3：P1 -> P2 ==========
struct MsgBundle_P1toP2 {
    mcl::bn::G2 X1;
    ZK::RDL_Proof   pi1_DL;
    BICYCL::CL_HSMqk::PublicKey ek;
    BICYCL::CL_HSMqk::CipherText ct_cl_x1;
    ZK::RCLDL_Proof pi1_CLDL;

    MsgBundle_P1toP2(
        const mcl::bn::G2& X1_,
        const ZK::RDL_Proof& pi1,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& ct,
        const ZK::RCLDL_Proof& pi2)
        : X1(X1_), pi1_DL(pi1), ek(ek), ct_cl_x1(ct), pi1_CLDL(pi2) {}
};

// ======================================================
// === Signing Phase Messages ===
// ======================================================

// --- Round 1: P1 -> P2 ---
struct MsgSign_P1toP2 {
    std::array<unsigned char, 32> beta1;  // 随机 β1（32B）
};

// --- Round 2: P2 -> P1 ---
struct MsgSign_P2toP1 {
    std::vector<uint8_t> vrf_proof;       // 97B proof (P1 自行验证并导出 β2)
    BICYCL::CL_HSMqk::CipherText CTb;     
    ZK::RCLLIN_Proof pi_CLLin;            
    mcl::bn::G1 R;
    
    MsgSign_P2toP1(
        const std::vector<uint8_t>& vrf_proof_,
        const BICYCL::CL_HSMqk::CipherText& CTb_,
        const ZK::RCLLIN_Proof& pi_CLLin_,
        const mcl::bn::G1& R_)
        : vrf_proof(vrf_proof_), CTb(CTb_), pi_CLLin(pi_CLLin_), R(R_) {}
};

