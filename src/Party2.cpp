#include "../include/Party2.h"
#include <iostream>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>
using namespace mcl::bn;
using namespace BICYCL;
using namespace GlobalContext;
using RDLProof   = ZK::RDL_Proof;
using RCLDLProof = ZK::RCLDL_Proof;


Party2::Party2()
  : rng_(),
    C_(BICYCL::Mpz("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
        1, BICYCL::SecLevel(128), rng_)
{
    // --- setup VRF ---
    vrf_ = ecvrf_p256_rfc9381();
    if (!vrf_) throw std::runtime_error("[Party2] ECVRF suite init failed");
    // === VRF keypair ===
    ec_key_ = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (!ec_key_ || EC_KEY_generate_key(ec_key_) != 1)
        throw std::runtime_error("[Party2] EC_KEY init failed");

    const BIGNUM* priv_bn = EC_KEY_get0_private_key(ec_key_);
    priv_ = BN_dup(priv_bn);
    const EC_POINT* pub_point = EC_KEY_get0_public_key(ec_key_);
    vrf_pub_ = EC_POINT_dup(pub_point, EC_KEY_get0_group(ec_key_));

    // std::cout << "[Party2] CL_HSMqk context and VRF keypair initialized.\n";
}

Party2::~Party2() {
    if (priv_) BN_free(priv_);
    if (ec_key_) EC_KEY_free(ec_key_);
}
// ========== Round 2: P2 -> P1 ==========
MsgBundle_P2toP1 Party2::round2(const MsgCommit_P1toP2& fromP1) {
    // 1) 采样并计算 X2 = g2^x2
    x2_.setByCSPRNG();
    mcl::bn::G2::mul(X2_, GlobalContext::G2(), x2_);

    // 2) 生成 RDL 证明
    RDLProof pi2_DL = ZK::RDL::prove("RDL", GlobalContext::G2(), X2_, x2_);

    // 4) 聚合初始化输出消息
    MsgBundle_P2toP1 out;
    out.X2 = X2_;
    out.pi2_DL = pi2_DL;
    out.vrf_pub = vrf_pub_;

    // std::cout << "[Party2] Round2: sent (X2, pi2_DL, vrf_pub).\n";
    return out;
}

// ========== Finalize (DKG完成于P2端)：验证并聚合公钥 ==========
mcl::bn::G2 Party2::finalize(const MsgBundle_P1toP2& fromP1, const MsgCommit_P1toP2& com1_from_round1) {
    // 1) 检查 com1 承诺
    {
        auto recomputed = ZK::compute_commitment(fromP1.X1, fromP1.pi1_DL);
        if (recomputed != com1_from_round1.com1) {
            throw std::runtime_error("[Party2] finalize: commitment mismatch!");
        }
    }

    // 2) 验证 P1 的 RDL / RCLDL
    {
        if (!ZK::RDL::verify("RDL", GlobalContext::G2(), fromP1.X1, fromP1.pi1_DL)) {
            throw std::runtime_error("[Party2] finalize: RDL verify failed.");
        }

        // 注意：P2 本地构造 CL_HSMqk 参数与 P1 相同即可
        RandGen rng_tmp;
        CL_HSMqk C_dup(BICYCL::Mpz("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
                       1, BICYCL::SecLevel(128), rng_tmp);

        if (!ZK::RCLDL::verify("RCLDL", GlobalContext::G2(), fromP1.X1,
                                C_dup, fromP1.ek, fromP1.ct_cl_x1, fromP1.pi1_CLDL)) {
            throw std::runtime_error("[Party2] finalize: RCLDL verify failed.");
        }
    }
    // === 保存来自 P1 的 CL 公钥与密文份额 ===
    // PublicKey、CipherText 无默认构造 ⇒ 用 unique_ptr 承接
    ek_from_P1_ = std::make_unique<BICYCL::CL_HSMqk::PublicKey>(fromP1.ek);
    ct_x1_from_P1_ = std::make_unique<BICYCL::CL_HSMqk::CipherText>(fromP1.ct_cl_x1);
    X1_ = fromP1.X1;

    // 3) 聚合联合公钥 X = X1 + X2
    mcl::bn::G2::add(X_, fromP1.X1, X2_);
    // std::cout << "[Party2] finalize: joint public key X generated.\n";
    return X_;
}

void Party2::setMessages(const std::vector<mcl::bn::Fr>& msgs) {
    if (msgs.size() != GlobalContext::H().size() - 1) {
        throw std::runtime_error("[Party2] Message length mismatch with bbs_ell");
    }
    messages_ = msgs;
}

MsgSign_P2toP1 Party2::sign_pass2(const MsgSign_P1toP2 &fromP1) {
    // === Step1: hash stored message vector ===
    unsigned char msg_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto &m : messages_) {
        std::string s = m.getStr(16);
        SHA256_Update(&ctx, s.data(), s.size());
    }
    SHA256_Final(msg_hash, &ctx);
    // === Step2: VRF proof ===
    unsigned char proof[97];
    memset(proof, 0, sizeof(proof));
    if (!ECVRF_prove_rfc9381(vrf_, vrf_pub_, priv_,
                             msg_hash, sizeof(msg_hash),
                             proof, sizeof(proof))) {
        throw std::runtime_error("[Party2] ECVRF_prove_rfc9381 failed");
    }

    // === Step3: β2 ← VRF proof to hash ===
    unsigned char beta2[32];
    ECVRF_proof_to_hash_rfc9381(vrf_, proof, sizeof(proof), beta2);

    // === Step4: H3(β1||β2) → (e,s) ∈ Zq^2 ===
    std::string concat;
    concat.reserve(64);
    concat.append(reinterpret_cast<const char*>(fromP1.beta1.data()), 32);
    concat.append(reinterpret_cast<const char*>(beta2), 32);
    mcl::bn::Fr e = GlobalContext::Environment::hashToFr(concat + "e");
    mcl::bn::Fr s = GlobalContext::Environment::hashToFr(concat + "s");
    // BIGNUM *e_bn = nullptr, *s_bn = nullptr;
    // H3_beta_concat_to_scalars(vrf_->group, fromP1.beta1.data(), beta2, &e_bn, &s_bn);
    // Fr e, s;
    // e.setStr(BN_bn2hex(e_bn));
    // s.setStr(BN_bn2hex(s_bn));


    // === Step5: Compute B = G1 + sH0 + Σ mi·Hi ===
    mcl::bn::G1 B;
    mcl::bn::G1 tmp,tmp2;
    G1::mul(tmp, GlobalContext::H()[0], s);
    G1::add(B, GlobalContext::G1(), tmp);
    for (size_t i = 0; i < messages_.size(); ++i) {
        G1::mul(tmp2, GlobalContext::H()[i + 1], messages_[i]);
        G1::add(B, B, tmp2);
    }

    // === Step6: R = B^r ===
    Fr r;
    r.setByCSPRNG();
    mcl::bn::G1 R;
    G1::mul(R, B, r);

    // === Step7: Enc(k = r·(x2+e)) ===
    Fr k = r * (x2_ + e);
    Mpz k_mpz; utils::fr_to_mpz(k_mpz, k);
    Mpz rho2 = rng_.random_mpz(C_.encrypt_randomness_bound());
    CL_HSMqk::CipherText CTk(C_, *ek_from_P1_, CL_HSMqk::ClearText(C_, k_mpz), rho2);

    // === Step8: Homomorphic combine CTa_r = (ct_x1)^r, CTb = CTa_r * CTk ===
    Mpz r_mpz; utils::fr_to_mpz(r_mpz, r);
    auto CTa_r(C_.scal_ciphertexts(*ek_from_P1_, *ct_x1_from_P1_, r_mpz, Mpz(0UL)));
    auto CTb(C_.add_ciphertexts(*ek_from_P1_, CTa_r, CTk, Mpz(0UL)));

    // === Step9: Zero-knowledge proof π_CLLIN ===
    auto pi_CLLin = ZK::RCLLIN::prove("RCLLIN", B, GlobalContext::H()[1],
                                      GlobalContext::G2(), C_, *ek_from_P1_,
                                      *ct_x1_from_P1_, CTb, R, X2_, r, x2_, e, rho2);

    // === Step10: send proof, R, CTb and π_CLLIN ===

    std::vector<uint8_t> vrf_vec(proof, proof + sizeof(proof));

    MsgSign_P2toP1 out(vrf_vec, CTb, pi_CLLin, R);

    // std::cout << "[Party2] Sign_Pass2: sent (vrf_proof, R, CTb, pi_CLLin).\n";
    return out;
}

