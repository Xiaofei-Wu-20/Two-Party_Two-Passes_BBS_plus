#pragma once
#include "global_context.h"
#include "bicycl/bicycl.hpp"
#include <mcl/bls12_381.hpp>
#include <string>
#include <vector>
#include <sstream>
#include "Utils.h"

// ===========================================================
// Σ-Protocol: 𝓡_DL  与  𝓡_CL-DL
// ===========================================================
namespace ZK {

// ---------- 工具 ----------
std::string ecPointToString(const mcl::bn::G1& P);
std::string ecPointToString(const mcl::bn::G2& P);
std::string qfiToString(const BICYCL::QFI& q);
std::string gtToString(const mcl::bn::GT& g);


// ---------- 关系 1: R_DL ----------
struct RDL_Proof {
    mcl::bn::G2 Z0;    // 承诺：Z0 = z0·G2
    mcl::bn::Fr z_star; // 响应：z* = z0 + ch·x
};

std::vector<uint8_t> compute_commitment(const mcl::bn::G2& X1, const RDL_Proof& pi);

struct RDL {
    static RDL_Proof prove(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& x);

    static bool verify(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const RDL_Proof& pi);
};

// ---------- 关系 2: R_CL-DL (缩小证明版本)----------
struct RCLDL_Proof {
    mcl::bn::Fr ch;       // challenge
    mcl::bn::Fr z_star;   // z* = z0 + ch·x
    BICYCL::Mpz dk_star;  // dk* = dk0 + ch·dk
};

struct RCLDL {
    static RCLDL_Proof prove(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& x,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::Mpz& dk,
        const BICYCL::CL_HSMqk::CipherText& Cx);

    static bool verify(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& Cx,
        const RCLDL_Proof& pi);
};
// ---------- 关系 2: R_CL-DL ----------
struct RCLDL_Proof2 {
    mcl::bn::G2 Z0;       // z0·G2
    BICYCL::QFI ek0;      // g_q^{dk0}
    BICYCL::QFI c2_tilde; // f^{z0} * c1^{dk0}
    mcl::bn::Fr z_star;   // z* = z0 + ch·x
    BICYCL::Mpz dk_star;  // dk* = dk0 + ch·dk
};

struct RCLDL2 {
    static RCLDL_Proof2 prove(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& x,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::Mpz& dk,
        const BICYCL::CL_HSMqk::CipherText& Cx);

    static bool verify(
        const std::string& domain,
        const mcl::bn::G2& G2,
        const mcl::bn::G2& X,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& Cx,
        const RCLDL_Proof2& pi);
};


// ---------- 关系 3: R_CL-Lin(缩小证明版本) ----------
struct RCLLIN_Proof {
    mcl::bn::G1 M;
    mcl::bn::Fr ch;
    mcl::bn::Fr beta_t;
    BICYCL::Mpz beta_r, beta_rx, beta_rho;
};
struct RCLLIN {
    static RCLLIN_Proof prove(
        const std::string& domain,
        const mcl::bn::G1& G1_,
        const mcl::bn::G1& H1,
        const mcl::bn::G2& G2_,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& CTa,
        const BICYCL::CL_HSMqk::CipherText& CTb,
        const mcl::bn::G1& R,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& r,
        const mcl::bn::Fr& x,
        const mcl::bn::Fr& e,
        const BICYCL::Mpz& rho);

    static bool verify(
        const std::string& domain,
        const mcl::bn::G1& G1_,
        const mcl::bn::G1& H1,
        const mcl::bn::G2& G2_,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& CTa,
        const BICYCL::CL_HSMqk::CipherText& CTb,
        const mcl::bn::G1& R,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& e,
        const RCLLIN_Proof& pi);
};
// ---------- 关系 3: R_CL-Lin ----------
struct RCLLIN_Proof2 {
    mcl::bn::G1 M;
    mcl::bn::G1 T_M;
    mcl::bn::GT T_alpha_t;
    mcl::bn::G1 T_alpha_r;
    BICYCL::QFI T1;
    BICYCL::QFI T2;
    mcl::bn::Fr beta_t;
    BICYCL::Mpz beta_r, beta_rx, beta_rho;
};
struct RCLLIN2 {
    static RCLLIN_Proof2 prove(
        const std::string& domain,
        const mcl::bn::G1& G1_,
        const mcl::bn::G1& H1,
        const mcl::bn::G2& G2_,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& CTa,
        const BICYCL::CL_HSMqk::CipherText& CTb,
        const mcl::bn::G1& R,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& r,
        const mcl::bn::Fr& x,
        const mcl::bn::Fr& e,
        const BICYCL::Mpz& rho);

    static bool verify(
        const std::string& domain,
        const mcl::bn::G1& G1_,
        const mcl::bn::G1& H1,
        const mcl::bn::G2& G2_,
        const BICYCL::CL_HSMqk& C,
        const BICYCL::CL_HSMqk::PublicKey& ek,
        const BICYCL::CL_HSMqk::CipherText& CTa,
        const BICYCL::CL_HSMqk::CipherText& CTb,
        const mcl::bn::G1& R,
        const mcl::bn::G2& X,
        const mcl::bn::Fr& e,
        const RCLLIN_Proof2& pi);
};



} // namespace ZK
