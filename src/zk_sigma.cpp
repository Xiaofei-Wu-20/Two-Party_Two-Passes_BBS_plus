#include "../include/global_context.h"
#include "../include/zk_sigma.h"
#include "../include/Utils.h"
#include "../include/bicycl/bicycl.hpp"
#include "../include/bicycl/bicycl/qfi.hpp"
#include "../include/bicycl/bicycl/CL_HSMqk.hpp"
#include "../include/bicycl/bicycl/CL_HSMqk.inl"
#include <iostream>
using namespace mcl::bn;
using namespace BICYCL;
using namespace GlobalContext;

namespace ZK {
std::string ecPointToString(const mcl::bn::G1& P) {
    std::ostringstream oss;
    oss << P;
    return oss.str();
}

std::string ecPointToString(const mcl::bn::G2& P) {
    std::ostringstream oss;
    oss << P;
    return oss.str();
}
std::string gtToString(const mcl::bn::GT& g) {
    std::stringstream ss;
    ss << g;
    return ss.str();
}

template <typename T>
void append_bytes(std::vector<uint8_t>& out, const T& val) {
    size_t size = val.serialize(nullptr, 0); // 先查询序列化所需长度
    std::vector<uint8_t> buf(size);
    val.serialize(buf.data(), size);         // 真正序列化写入字节
    out.insert(out.end(), buf.begin(), buf.end());
}

// 生成 Com1 = SHA256(X1 || pi1_DL)
std::vector<uint8_t> compute_commitment(const mcl::bn::G2& X, const RDL_Proof& pi) {
    std::vector<uint8_t> data;
    append_bytes(data, X);
    append_bytes(data, pi.Z0);
    append_bytes(data, pi.z_star);

    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);
    SHA256(data.data(), data.size(), hash.data());
    return hash;
}

// ===========================================================
// Σ-protocol for 𝓡_DL: X = x·G2
// ===========================================================
ZK::RDL_Proof ZK::RDL::prove(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const Fr& x)
{
    GlobalContext::init();
    RDL_Proof pi;
    Fr z0; z0.setRand();
    G2::mul(pi.Z0, G2_, z0);

    std::string data = domain + ecPointToString(G2_) + ecPointToString(X) + ecPointToString(pi.Z0);
    Fr ch = GlobalContext::Environment::hashToFr(data);

    pi.z_star = z0 + ch * x;
    return pi;
}

bool ZK::RDL::verify(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const RDL_Proof& pi)
{
    std::string data = domain + ecPointToString(G2_) + ecPointToString(X) + ecPointToString(pi.Z0);
    Fr ch = GlobalContext::Environment::hashToFr(data);

    mcl::bn::G2 left, right, tmp;
    G2::mul(left, G2_, pi.z_star);
    G2::mul(tmp, X, ch);
    G2::add(right, pi.Z0, tmp);
    return left == right;
}



// ===========================================================
// Σ-protocol for 𝓡_CL-DL(缩小证明版本)
// ===========================================================
ZK::RCLDL_Proof ZK::RCLDL::prove(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const Fr& x,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const Mpz& dk,
    const CL_HSMqk::CipherText& Cx)
{
    RandGen randgen;
    Mpz upperBound("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"); 

    RCLDL_Proof pi;
    Fr z0; z0.setByCSPRNG();
    // 生成一个 0 ≤ dk0 < upperBound 的随机 Mpz
    Mpz dk0 = randgen.random_mpz(upperBound);
    // commitments
    mcl::bn::G2 Z0;       // z0·G2
    QFI ek0;      // g_q^{dk0}
    QFI c2_tilde; // f^{z0} * c1^{dk0}
    G2::mul(Z0, G2_, z0);
    C.power_of_h(ek0, dk0); // g_q^{dk0}
    Mpz z0_mpz;
    utils::fr_to_mpz(z0_mpz, z0);// f^z0
    QFI fz0 = C.power_of_f(z0_mpz);
    QFI c1dk0;
    C.Cl_Delta().nupow(c1dk0, Cx.c1(), dk0); // c1^dk0
    C.Cl_Delta().nucomp(c2_tilde, fz0, c1dk0); // c2_tilde = f^z0 * c1^dk0

    // Fiat-Shamir
    std::string data = domain +
        ecPointToString(G2_) + ecPointToString(X) + ecPointToString(Z0) +
        qfiToString(ek0) + qfiToString(c2_tilde) +
        qfiToString(Cx.c1()) + qfiToString(Cx.c2());

    pi.ch = GlobalContext::Environment::hashToFr(data);
    // response
    pi.z_star = z0 + pi.ch * x;
    Mpz ch_mpz;
    utils::fr_to_mpz(ch_mpz, pi.ch);
    Mpz ch_mul_dk;
    Mpz::mul(ch_mul_dk, ch_mpz, dk);
    Mpz::add(pi.dk_star, dk0, ch_mul_dk); // pi.dk_star = dk0 + ch_mul_dk
    return pi;
}

bool ZK::RCLDL::verify(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& Cx,
    const RCLDL_Proof& pi)
{
    // z_star * G2 == Z0 + ch * X
    mcl::bn::G2 lhs1, rhs1, tmp1;
    G2::mul(lhs1, G2_, pi.z_star);
    G2::mul(tmp1, X, pi.ch);
    mcl::bn::G2 Z0=lhs1-tmp1;

    // g_q^{dk_star} == ek0 * ek^{ch}
    QFI lhs2, rhs2_ch, ek0;
    Mpz ch_mpz;
    utils::fr_to_mpz(ch_mpz, pi.ch);

    // lhs = g_q^{dk_star}
    C.power_of_h(lhs2, pi.dk_star);

    // rhs = ek0 * ek^ch
    C.Cl_Delta().nupow(rhs2_ch, ek.elt(), ch_mpz);  // ek^ch
    C.Cl_Delta().nucompinv(ek0, lhs2, rhs2_ch);      // ek0 = g_q^{dk_star} *ek^(-ch)

    // f^{z_star} * c1^{dk_star} == c2_tilde * c2^{ch}
    QFI lhs3_fz, lhs3_c1, lhs3;
    QFI rhs3_c2, c2_tilde;

    // lhs = f^{z_star} * c1^{dk_star}
    Mpz z_star_mpz;
    utils::fr_to_mpz(z_star_mpz, pi.z_star);
    lhs3_fz = C.power_of_f(z_star_mpz);
    C.Cl_Delta().nupow(lhs3_c1, Cx.c1(), pi.dk_star);
    C.Cl_Delta().nucomp(lhs3, lhs3_fz, lhs3_c1);

    // rhs = c2_tilde * c2^ch
    C.Cl_Delta().nupow(rhs3_c2, Cx.c2(), ch_mpz);
    C.Cl_Delta().nucompinv(c2_tilde, lhs3, rhs3_c2); // ek0 = f^{z_star} * c1^{dk_star} *c2^(-ch)


    // Fiat-Shamir
    std::string data = domain +
        ecPointToString(G2_) + ecPointToString(X) + ecPointToString(Z0) +
        qfiToString(ek0) + qfiToString(c2_tilde) +
        qfiToString(Cx.c1()) + qfiToString(Cx.c2());

    Fr ch = GlobalContext::Environment::hashToFr(data);
    return pi.ch == ch;

}
// ===========================================================
// Σ-protocol for 𝓡_CL-DL
// ===========================================================
ZK::RCLDL_Proof2 ZK::RCLDL2::prove(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const Fr& x,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const Mpz& dk,
    const CL_HSMqk::CipherText& Cx)
{
    RandGen randgen;
    Mpz upperBound("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"); 

    RCLDL_Proof2 pi;
    Fr z0; z0.setByCSPRNG();
    // 生成一个 0 ≤ dk0 < upperBound 的随机 Mpz
    Mpz dk0 = randgen.random_mpz(upperBound);
    // commitments
    G2::mul(pi.Z0, G2_, z0);
    C.power_of_h(pi.ek0, dk0); // g_q^{dk0}
    Mpz z0_mpz;
    utils::fr_to_mpz(z0_mpz, z0);// f^z0
    QFI fz0 = C.power_of_f(z0_mpz);
    QFI c1dk0;
    C.Cl_Delta().nupow(c1dk0, Cx.c1(), dk0); // c1^dk0
    C.Cl_Delta().nucomp(pi.c2_tilde, fz0, c1dk0); // c2_tilde = f^z0 * c1^dk0

    // Fiat-Shamir
    std::string data = domain +
        ecPointToString(G2_) + ecPointToString(X) + ecPointToString(pi.Z0) +
        qfiToString(pi.ek0) + qfiToString(pi.c2_tilde) +
        qfiToString(Cx.c1()) + qfiToString(Cx.c2());

    Fr ch = GlobalContext::Environment::hashToFr(data);

    // response
    pi.z_star = z0 + ch * x;
    Mpz ch_mpz;
    utils::fr_to_mpz(ch_mpz, ch);  
    Mpz ch_mul_dk;
    Mpz::mul(ch_mul_dk, ch_mpz, dk);
    Mpz::add(pi.dk_star, dk0, ch_mul_dk); // pi.dk_star = dk0 + ch_mul_dk
    return pi;
}
bool ZK::RCLDL2::verify(
    const std::string& domain,
    const mcl::bn::G2& G2_,
    const mcl::bn::G2& X,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& Cx,
    const RCLDL_Proof2& pi)
{
    // Fiat-Shamir
    std::string data = domain +
        ecPointToString(G2_) + ecPointToString(X) + ecPointToString(pi.Z0) +
        qfiToString(pi.ek0) + qfiToString(pi.c2_tilde) +
        qfiToString(Cx.c1()) + qfiToString(Cx.c2());

    Fr ch = GlobalContext::Environment::hashToFr(data);
    
    // z_star * G2 == Z0 + ch * X
    mcl::bn::G2 lhs1, rhs1, tmp1;
    G2::mul(lhs1, G2_, pi.z_star);
    G2::mul(tmp1, X, ch);
    G2::add(rhs1, pi.Z0, tmp1);
    if (lhs1 != rhs1) return false;

    // g_q^{dk_star} == ek0 * ek^{ch}
    QFI lhs2, rhs2_ch, rhs2;
    Mpz ch_mpz;
    utils::fr_to_mpz(ch_mpz, ch);

    // lhs = g_q^{dk_star}
    C.power_of_h(lhs2, pi.dk_star);

    // rhs = ek0 * ek^ch
    C.Cl_Delta().nupow(rhs2_ch, ek.elt(), ch_mpz);  // ek^ch
    C.Cl_Delta().nucomp(rhs2, pi.ek0, rhs2_ch);
    if (!(lhs2 == rhs2)) return false;

    // f^{z_star} * c1^{dk_star} == c2_tilde * c2^{ch}
    QFI lhs3_fz, lhs3_c1, lhs3;
    QFI rhs3_c2, rhs3;

    // lhs = f^{z_star} * c1^{dk_star}
    Mpz z_star_mpz;
    utils::fr_to_mpz(z_star_mpz, pi.z_star);
    lhs3_fz = C.power_of_f(z_star_mpz);
    C.Cl_Delta().nupow(lhs3_c1, Cx.c1(), pi.dk_star);
    C.Cl_Delta().nucomp(lhs3, lhs3_fz, lhs3_c1);

    // rhs = c2_tilde * c2^ch
     C.Cl_Delta().nupow(rhs3_c2, Cx.c2(), ch_mpz); 
     C.Cl_Delta().nucomp(rhs3, pi.c2_tilde, rhs3_c2); // 比较 
     return lhs3 == rhs3;
}


// ===========================================================
// Σ-protocol for 𝓡_CL-Lin(缩小证明版本)
// ===========================================================
ZK::RCLLIN_Proof ZK::RCLLIN::prove(
    const std::string& domain,
    const mcl::bn::G1& G1_, const mcl::bn::G1& H1, const mcl::bn::G2& G2_,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& CTa,
    const CL_HSMqk::CipherText& CTb,
    const mcl::bn::G1& R,
    const mcl::bn::G2& X,
    const Fr& r, const Fr& x, const Fr& e,
    const Mpz& rho)
{
    RandGen randgen;
    RCLLIN_Proof pi;
    // M = r*x*G1 + t*H1 
    Fr t; 
    t.setByCSPRNG();            
    Fr rx = r * (x + e);              
    mcl::bn::G1 rxG1, tH1;               
    G1::mul(rxG1, G1_, rx);     // rxG1 = r·(x+e)·G1
    G1::mul(tH1, H1, t);        // tH1  = t·H1
    G1::add(pi.M, rxG1, tH1);   // M = r·(x+e)·G1 + t·H1

    // α_r, α_rx, α_t, α_ρ
    Fr alpha_r, alpha_rx, alpha_t;
    alpha_r.setByCSPRNG();
    alpha_rx.setByCSPRNG();
    alpha_t.setByCSPRNG();
    // 使用 CL 系统加密随机性范围生成 α_ρ
    Mpz alpha_rho = randgen.random_mpz(C.encrypt_randomness_bound());

    //  T_M = α_rx·G1 + α_t·H1 
    mcl::bn::G1 T_M, tmp1, tmp2;
    G1::mul(tmp1, G1_, alpha_rx); 
    G1::mul(tmp2, H1, alpha_t); 
    G1::add(T_M, tmp1, tmp2);  // T_M = α_rx·G1 + α_t·H1

    GT G_T, G_H;
    mcl::bn::pairing(G_T, G1_, G2_);
    mcl::bn::pairing(G_H, H1, G2_);
    // T_{alpha_t} = alpha_t · G_H
    GT T_alpha_t;
    GT::pow(T_alpha_t, G_H, alpha_t);

    // T_{alpha_r} = alpha_r · G1
    mcl::bn::G1 T_alpha_r;
    G1::mul(T_alpha_r, G1_, alpha_r);

    //  T1 = c1^{α_r} * g_q^{α_ρ}
    Mpz alpha_r_mpz;
    utils::fr_to_mpz(alpha_r_mpz, alpha_r);  // Fr → Mpz
    QFI T1_c1_pow, T1_h_pow;
    C.Cl_Delta().nupow(T1_c1_pow, CTa.c1(), alpha_r_mpz); // c1^{α_r}
    C.power_of_h(T1_h_pow, alpha_rho);                  // g_q^{α_ρ}
    QFI T1;
    C.Cl_Delta().nucomp(T1, T1_c1_pow, T1_h_pow);       // T1 = c1^{α_r} * g_q^{α_ρ}
    

    //  T2 = c2^{α_r} * f^{α_rx} * ek^{α_ρ}
    QFI T2_c2_pow, T2_ek_pow, T2_tmp, T2;
    C.Cl_Delta().nupow(T2_c2_pow, CTa.c2(), alpha_r_mpz);// c2^{α_r}
    Mpz alpha_rx_mpz;
    utils::fr_to_mpz(alpha_rx_mpz, alpha_rx);
    QFI T2_f_pow=C.power_of_f(alpha_rx_mpz);               // f^{α_rx}
    C.Cl_Delta().nupow(T2_ek_pow, ek.elt(), alpha_rho);       // ek^{α_ρ}
    C.Cl_Delta().nucomp(T2_tmp, T2_c2_pow, T2_f_pow);  //c2^{α_r} * f^{α_rx}
    C.Cl_Delta().nucomp(T2, T2_tmp, T2_ek_pow);    //  T2 = c2^{α_r} * f^{α_rx} * ek^{α_ρ}


    // === Fiat–Shamir Challenge ===
    std::string fs_data = domain
        + ecPointToString(G1_) + ecPointToString(H1) + ecPointToString(G2_)
        + ecPointToString(R) + ecPointToString(X)
        + qfiToString(CTa.c1()) + qfiToString(CTa.c2())
        + qfiToString(CTb.c1()) + qfiToString(CTb.c2())
        + ecPointToString(pi.M)
        + ecPointToString(T_M)
        + gtToString(T_alpha_t)
        + ecPointToString(T_alpha_r)
        + qfiToString(T1)
        + qfiToString(T2);

    Fr ch = GlobalContext::Environment::hashToFr(fs_data);
    pi.ch = ch;

    // responses
    pi.beta_t  = alpha_t + ch * t;
    // pi.beta_r  = alpha_r + ch * r;
    // pi.beta_rx = alpha_rx + ch * rx;
    // Mpz ch_mpz, ch_mul_rho;
    // utils::fr_to_mpz(ch_mpz, ch);
    // Mpz::mul(ch_mul_rho, ch_mpz, rho);
    // Mpz::add(pi.beta_rho, alpha_rho, ch_mul_rho);

    // 关键：类群指数需要“整数和”，这里直接存到 Mpz 字段里
    Mpz ch_mpz, r_mpz, rx_mpz, ar_mpz, arx_mpz, tmp;
    utils::fr_to_mpz(ch_mpz, ch);
    utils::fr_to_mpz(r_mpz,  r);
    utils::fr_to_mpz(rx_mpz, rx);
    utils::fr_to_mpz(ar_mpz,  alpha_r);
    utils::fr_to_mpz(arx_mpz, alpha_rx);

     // beta_r = alpha_r + ch * r  （整数域，不取模）
    Mpz::mul(tmp, ch_mpz, r_mpz);
    Mpz::add(pi.beta_r, ar_mpz, tmp);

    // beta_rx = alpha_rx + ch * rx（整数域，不取模）
    Mpz::mul(tmp, ch_mpz, rx_mpz);
    Mpz::add(pi.beta_rx, arx_mpz, tmp);

    // beta_rho = alpha_rho + ch * rho（整数域，不取模）
    Mpz ch_rho; Mpz::mul(ch_rho, ch_mpz, rho);
    Mpz::add(pi.beta_rho, alpha_rho, ch_rho);

    return pi;
}

bool ZK::RCLLIN::verify(
    const std::string& domain,
    const mcl::bn::G1& G1_, const mcl::bn::G1& H1, const mcl::bn::G2& G2_,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& CTa,
    const CL_HSMqk::CipherText& CTb,
    const mcl::bn::G1& R,
    const mcl::bn::G2& X,
    const Fr& e,
    const RCLLIN_Proof& pi)
{
    mcl::bn::G1 T_M, T_alpha_r;
    GT T_alpha_t;
    QFI T1, T2;
    GT G_T, G_H;
    mcl::bn::pairing(G_T, G1_, G2_);
    mcl::bn::pairing(G_H, H1, G2_);

    Fr beta_r_fr, beta_rx_fr;
    utils::mpz_to_fr(beta_r_fr, pi.beta_r);   // 按曲线阶取模
    utils::mpz_to_fr(beta_rx_fr, pi.beta_rx); // 按曲线阶取模
    
    // (i)  G1:   β_rx·G1 + β_t·H1 == T_M + ch·M
    mcl::bn::G1 lhs, lhs1, lhs12, rhs1;
    G1::mul(lhs1, G1_, beta_rx_fr);
    G1::mul(lhs12, H1, pi.beta_t);
    G1::add(lhs, lhs1, lhs12);
    G1::mul(rhs1, pi.M, pi.ch);
    G1::sub(T_M, lhs, rhs1);
    
    // (ii) GT:   G_H^{β_t} == T_alpha_t * (e(M,G2)/e(R,X+eG2))^{ch}
    GT lhs2, rhs2, eMG2, eRXeG2, tmp, rhs2_inv;
    mcl::bn::G2 tmpG2;
    GT::pow(lhs2, G_H, pi.beta_t);       // lhs = G_H ^ beta_t = β_t · G_H
    mcl::bn::pairing(eMG2, pi.M, G2_);  // e(M, G2)
    mcl::bn::G2 X_plus_eG2;
    G2::mul(tmpG2, G2_, e);             // tmpG2 = e * G2
    G2::add(X_plus_eG2, X, tmpG2);     // X + e·G2
    mcl::bn::pairing(eRXeG2, R, X_plus_eG2);  // e(R, X + e·G2)
    GT::unitaryInv(tmp, eRXeG2);       // tmp = 1 / e(R, X + eG2)
    GT::mul(rhs2, eMG2, tmp);           // rhs = e(M, G2) / e(R, X + eG2)
    GT::pow(rhs2, rhs2, pi.ch);             // rhs = (e(M, G2)/e(R, X+eG2))^ch
    GT::unitaryInv(rhs2_inv, rhs2);             // rhs = (e(M, G2)/e(R, X+eG2))^{-ch}
    GT::mul(T_alpha_t, lhs2, rhs2_inv);               // T_alpha_t = G_H^{β_t} * (e(M,G2)/e(R,X+eG2))^{-ch}
    
    // (iii) G1:  β_r·G1 == T_alpha_r + ch·R
    mcl::bn::G1 lhs3,rhs3;
    G1::mul(lhs3, G1_, beta_r_fr);
    G1::mul(rhs3, R, pi.ch);
    G1::sub(T_alpha_r, lhs3, rhs3);

    Mpz ch_mpz; utils::fr_to_mpz(ch_mpz, pi.ch);

    // T1_left = c1^{beta_r} * g_q^{beta_rho}
    QFI t1_left, t1_tmp1, t1_tmp2;
    C.Cl_Delta().nupow(t1_tmp1, CTa.c1(), pi.beta_r);
    C.power_of_h(t1_tmp2, pi.beta_rho);
    C.Cl_Delta().nucomp(t1_left, t1_tmp1, t1_tmp2);

    // T1_right = d1^{ch}
    QFI t1_right;
    C.Cl_Delta().nupow(t1_right, CTb.c1(), ch_mpz);
    C.Cl_Delta().nucompinv(T1, t1_left, t1_right); // T1 = t1_left * d1^{-ch}

    Mpz beta_rx_mpz;
    utils::fr_to_mpz(beta_rx_mpz, beta_rx_fr);
    // T2_left = c2^{beta_r} * f^{beta_rx} * ek^{beta_rho}
    QFI t2_tmp1, t2_tmp2, t2_tmp3, t2_left1, t2_left;
    C.Cl_Delta().nupow(t2_tmp1, CTa.c2(), pi.beta_r);       // c2^{beta_r}
    t2_tmp2 = C.power_of_f(beta_rx_mpz);                    // f^{beta_rx}
    C.Cl_Delta().nupow(t2_tmp3, ek.elt(), pi.beta_rho);           // ek^{beta_rho}
    C.Cl_Delta().nucomp(t2_left1, t2_tmp1, t2_tmp2);          // c2^{beta_r} * f^{beta_rx}
    C.Cl_Delta().nucomp(t2_left, t2_left1, t2_tmp3);          // (-) * ek^{beta_rho}

    // T2_right = d2^{ch}
    QFI t2_right;
    C.Cl_Delta().nupow(t2_right, CTb.c2(), ch_mpz);          // d2^{ch}

    // T2 = t2_left * (t2_right)^(-1)
    C.Cl_Delta().nucompinv(T2, t2_left, t2_right);

    // Fiat–Shamir challenge
    std::string fs_data = domain
        + ecPointToString(G1_) + ecPointToString(H1) + ecPointToString(G2_)
        + ecPointToString(R) + ecPointToString(X)
        + qfiToString(CTa.c1()) + qfiToString(CTa.c2())
        + qfiToString(CTb.c1()) + qfiToString(CTb.c2())
        + ecPointToString(pi.M)
        + ecPointToString(T_M)
        + gtToString(T_alpha_t)
        + ecPointToString(T_alpha_r)
        + qfiToString(T1)
        + qfiToString(T2);

    Fr ch = GlobalContext::Environment::hashToFr(fs_data);

    //  challenge check
    return pi.ch == ch;
}

// ===========================================================
// Σ-protocol for 𝓡_CL-Lin
// ===========================================================
ZK::RCLLIN_Proof2 ZK::RCLLIN2::prove(
    const std::string& domain,
    const mcl::bn::G1& G1_, const mcl::bn::G1& H1, const mcl::bn::G2& G2_,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& CTa,
    const CL_HSMqk::CipherText& CTb,
    const mcl::bn::G1& R,
    const mcl::bn::G2& X,
    const Fr& r, const Fr& x, const Fr& e,
    const Mpz& rho)
{
    RandGen randgen;
    RCLLIN_Proof2 pi;
    // M = r*x*G1 + t*H1 
    Fr t; 
    t.setByCSPRNG();            
    Fr rx = r * (x + e);              
    mcl::bn::G1 rxG1, tH1;               
    G1::mul(rxG1, G1_, rx);     // rxG1 = r·(x+e)·G1
    G1::mul(tH1, H1, t);        // tH1  = t·H1
    G1::add(pi.M, rxG1, tH1);   // M = r·(x+e)·G1 + t·H1

    // α_r, α_rx, α_t, α_ρ
    Fr alpha_r, alpha_rx, alpha_t;
    alpha_r.setByCSPRNG();
    alpha_rx.setByCSPRNG();
    alpha_t.setByCSPRNG();
    // 使用 CL 系统加密随机性范围生成 α_ρ
    Mpz alpha_rho = randgen.random_mpz(C.encrypt_randomness_bound());

    //  T_M = α_rx·G1 + α_t·H1 
    mcl::bn::G1 tmp1, tmp2;
    G1::mul(tmp1, G1_, alpha_rx); 
    G1::mul(tmp2, H1, alpha_t); 
    G1::add(pi.T_M, tmp1, tmp2);  // T_M = α_rx·G1 + α_t·H1

    GT G_T, G_H;
    mcl::bn::pairing(G_T, G1_, G2_);
    mcl::bn::pairing(G_H, H1, G2_);
    // T_{alpha_t} = alpha_t · G_H
    GT::pow(pi.T_alpha_t, G_H, alpha_t);

    // T_{alpha_r} = alpha_r · G1
    G1::mul(pi.T_alpha_r, G1_, alpha_r);

    //  T1 = c1^{α_r} * g_q^{α_ρ}
    Mpz alpha_r_mpz;
    utils::fr_to_mpz(alpha_r_mpz, alpha_r);  // Fr → Mpz
    QFI T1_c1_pow, T1_h_pow;
    C.Cl_Delta().nupow(T1_c1_pow, CTa.c1(), alpha_r_mpz); // c1^{α_r}
    C.power_of_h(T1_h_pow, alpha_rho);                  // g_q^{α_ρ}
    C.Cl_Delta().nucomp(pi.T1, T1_c1_pow, T1_h_pow);       // T1 = c1^{α_r} * g_q^{α_ρ}
    

    //  T2 = c2^{α_r} * f^{α_rx} * ek^{α_ρ}
    QFI T2_c2_pow, T2_ek_pow, T2_tmp;
    C.Cl_Delta().nupow(T2_c2_pow, CTa.c2(), alpha_r_mpz);// c2^{α_r}
    Mpz alpha_rx_mpz;
    utils::fr_to_mpz(alpha_rx_mpz, alpha_rx);
    QFI T2_f_pow=C.power_of_f(alpha_rx_mpz);               // f^{α_rx}
    C.Cl_Delta().nupow(T2_ek_pow, ek.elt(), alpha_rho);       // ek^{α_ρ}
    C.Cl_Delta().nucomp(T2_tmp, T2_c2_pow, T2_f_pow);  //c2^{α_r} * f^{α_rx}
    C.Cl_Delta().nucomp(pi.T2, T2_tmp, T2_ek_pow);    //  T2 = c2^{α_r} * f^{α_rx} * ek^{α_ρ}


    // === Fiat–Shamir Challenge ===
    std::string fs_data = domain
        + ecPointToString(G1_) + ecPointToString(H1) + ecPointToString(G2_)
        + ecPointToString(R) + ecPointToString(X)
        + qfiToString(CTa.c1()) + qfiToString(CTa.c2())
        + qfiToString(CTb.c1()) + qfiToString(CTb.c2())
        + ecPointToString(pi.M)
        + ecPointToString(pi.T_M)
        + gtToString(pi.T_alpha_t)
        + ecPointToString(pi.T_alpha_r)
        + qfiToString(pi.T1)
        + qfiToString(pi.T2);

    Fr ch = GlobalContext::Environment::hashToFr(fs_data);

    // responses
    pi.beta_t  = alpha_t + ch * t;
    // pi.beta_r  = alpha_r + ch * r;
    // pi.beta_rx = alpha_rx + ch * rx;
    // Mpz ch_mpz, ch_mul_rho;
    // utils::fr_to_mpz(ch_mpz, ch);
    // Mpz::mul(ch_mul_rho, ch_mpz, rho);
    // Mpz::add(pi.beta_rho, alpha_rho, ch_mul_rho);

     // 关键：类群指数需要“整数和”，这里直接存到 Mpz 字段里
    Mpz ch_mpz, r_mpz, rx_mpz, ar_mpz, arx_mpz, tmp;
    utils::fr_to_mpz(ch_mpz, ch);
    utils::fr_to_mpz(r_mpz,  r);
    utils::fr_to_mpz(rx_mpz, rx);
    utils::fr_to_mpz(ar_mpz,  alpha_r);
    utils::fr_to_mpz(arx_mpz, alpha_rx);

    // beta_r = alpha_r + ch * r  （整数域，不取模）
    Mpz::mul(tmp, ch_mpz, r_mpz);
    Mpz::add(pi.beta_r, ar_mpz, tmp);

    // beta_rx = alpha_rx + ch * rx（整数域，不取模）
    Mpz::mul(tmp, ch_mpz, rx_mpz);
    Mpz::add(pi.beta_rx, arx_mpz, tmp);

    // beta_rho = alpha_rho + ch * rho（整数域，不取模）
    Mpz ch_rho; Mpz::mul(ch_rho, ch_mpz, rho);
    Mpz::add(pi.beta_rho, alpha_rho, ch_rho);

    return pi;
}

bool ZK::RCLLIN2::verify(
    const std::string& domain,
    const mcl::bn::G1& G1_, const mcl::bn::G1& H1, const mcl::bn::G2& G2_,
    const CL_HSMqk& C,
    const CL_HSMqk::PublicKey& ek,
    const CL_HSMqk::CipherText& CTa,
    const CL_HSMqk::CipherText& CTb,
    const mcl::bn::G1& R,
    const mcl::bn::G2& X,
    const Fr& e,
    const RCLLIN_Proof2& pi)
{
    // Fiat–Shamir challenge
    std::string fs_data = domain
        + ecPointToString(G1_) + ecPointToString(H1) + ecPointToString(G2_)
        + ecPointToString(R) + ecPointToString(X)
        + qfiToString(CTa.c1()) + qfiToString(CTa.c2())
        + qfiToString(CTb.c1()) + qfiToString(CTb.c2())
        + ecPointToString(pi.M)
        + ecPointToString(pi.T_M)
        + gtToString(pi.T_alpha_t)
        + ecPointToString(pi.T_alpha_r)
        + qfiToString(pi.T1)
        + qfiToString(pi.T2);

    Fr ch = GlobalContext::Environment::hashToFr(fs_data);
    GT G_T, G_H;
    mcl::bn::pairing(G_T, G1_, G2_);
    mcl::bn::pairing(G_H, H1, G2_);

    Fr beta_r_fr, beta_rx_fr;
    utils::mpz_to_fr(beta_r_fr, pi.beta_r);   // 按曲线阶取模
    utils::mpz_to_fr(beta_rx_fr, pi.beta_rx); // 按曲线阶取模

    // (i)  G1:   β_rx·G1 + β_t·H1 == T_M + ch·M
    mcl::bn::G1 lhs, lhs1, lhs2, rhs;
    G1::mul(lhs1, G1_, beta_rx_fr);
    G1::mul(lhs2, H1,  pi.beta_t);
    G1::add(lhs, lhs1, lhs2);
    mcl::bn::G1 chM; G1::mul(chM, pi.M, ch);
    G1::add(rhs, pi.T_M, chM);
    if (lhs != rhs) return false;

    // (ii) GT:   G_H^{β_t} == T_alpha_t * (e(M,G2)/e(R,X+eG2))^{ch}
    GT lhsGT, rhsGT, eMG2, eRXeG2, tmpGT;
    GT::pow(lhsGT, G_H, pi.beta_t);
    mcl::bn::pairing(eMG2, pi.M, G2_);
    mcl::bn::G2 Xpe; 
    mcl::bn::G2 tmpG2; 
    mcl::bn::G2::mul(tmpG2, G2_, e);
    G2::add(Xpe, X, tmpG2);
    mcl::bn::pairing(eRXeG2, R, Xpe);
    GT::unitaryInv(tmpGT, eRXeG2);
    GT::mul(rhsGT, eMG2, tmpGT);
    GT::pow(rhsGT, rhsGT, ch);
    GT::mul(rhsGT, pi.T_alpha_t, rhsGT);
    if (lhsGT != rhsGT) return false;

    // (iii) G1:  β_r·G1 == T_alpha_r + ch·R
    mcl::bn::G1 lhs3, rhs3, chR;
    G1::mul(lhs3, G1_, beta_r_fr);
    G1::mul(chR, R, ch);
    G1::add(rhs3, pi.T_alpha_r, chR);
    if (lhs3 != rhs3) return false;

    Mpz ch_mpz; utils::fr_to_mpz(ch_mpz, ch);

    // T1: c1^{β_r} * g_q^{β_ρ} == T1 * d1^{ch}
    QFI t1_left_c1, t1_left_h, t1_left, t1_right_pow, t1_right;
    C.Cl_Delta().nupow(t1_left_c1, CTa.c1(), pi.beta_r);    // β_r (Mpz)
    C.power_of_h(t1_left_h,      pi.beta_rho);              // β_ρ (Mpz)
    C.Cl_Delta().nucomp(t1_left, t1_left_c1, t1_left_h);
    C.Cl_Delta().nupow(t1_right_pow, CTb.c1(), ch_mpz);    // d1^{ch}
    C.Cl_Delta().nucomp(t1_right, pi.T1, t1_right_pow);    // T1 * d1^{ch}
    if (!(t1_left == t1_right)) return false;

    // T2: c2^{β_r} * f^{β_rx} * ek^{β_ρ} == T2 * d2^{ch}
    QFI t2_c2, t2_f, t2_ek, t2_left, t2_right_pow, t2_right;
    C.Cl_Delta().nupow(t2_c2, CTa.c2(), pi.beta_r);        // β_r (Mpz)
    t2_f = C.power_of_f(pi.beta_rx);                       // β_rx (Mpz)
    C.Cl_Delta().nupow(t2_ek, ek.elt(), pi.beta_rho);     // β_ρ (Mpz)
    C.Cl_Delta().nucomp(t2_left, t2_c2, t2_f);
    C.Cl_Delta().nucomp(t2_left, t2_left, t2_ek);
    C.Cl_Delta().nupow(t2_right_pow, CTb.c2(), ch_mpz);    // d2^{ch}
    C.Cl_Delta().nucomp(t2_right, pi.T2, t2_right_pow);    // T2 * d2^{ch}
    if (!(t2_left == t2_right)) return false;
    
    return true;

}

}

std::string ZK::qfiToString(const QFI& q) {
    std::ostringstream oss;
    oss << q;
    return oss.str();
}


