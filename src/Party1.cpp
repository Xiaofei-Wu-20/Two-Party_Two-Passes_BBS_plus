#include "../include/global_context.h"
#include "../include/Party1.h"
#include <iostream>
using namespace mcl::bn;
using namespace BICYCL;
using namespace GlobalContext;

using RDLProof   = ZK::RDL_Proof;
using RCLDLProof = ZK::RCLDL_Proof;


Party1::Party1()
  : rng_(),
    C_(Mpz("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
        1, SecLevel(128), rng_)
{
    dk_mpz_ = rng_.random_mpz(C_.encrypt_randomness_bound());
    BICYCL::CL_HSMqk::SecretKey dk(C_, dk_mpz_);
    dk_ = std::make_unique<BICYCL::CL_HSMqk::SecretKey>(dk);
    ek_ = std::make_unique<BICYCL::CL_HSMqk::PublicKey>(C_.keygen(*dk_));

    // std::cout << "[Party1] CL params and keys initialized.\n";
}
Party1::~Party1() {
    if (vrf_pub_) EC_POINT_free(vrf_pub_);
    if (ec_group_) EC_GROUP_free(ec_group_);
}

BICYCL::CL_HSMqk::ClearText Party1::decrypt_CT(const BICYCL::CL_HSMqk::CipherText& ct) const {
    if (!dk_) throw std::runtime_error("[Party1] decrypt_CT: SecretKey not initialized.");
    return C_.decrypt(*dk_, ct);
}

// ========== Round 1: P1 -> P2 发送 com1 ==========
MsgCommit_P1toP2 Party1::round1() {
    x1_.setByCSPRNG();
    G2::mul(X1_, GlobalContext::G2(), x1_);

    RDLProof pi1_DL = ZK::RDL::prove("RDL", GlobalContext::G2(), X1_, x1_);
    com1_cached_ = ZK::compute_commitment(X1_, pi1_DL);

    MsgCommit_P1toP2 out;
    out.com1 = com1_cached_;
    // std::cout << "[Party1] Round1: sent com1.\n";
    return out;
}
// ========== Round 3: P1 -> P2 发送 (X1, pi1_DL, ek, Enc(x1), pi1_CLDL) ==========
MsgBundle_P1toP2 Party1::round3(const MsgBundle_P2toP1& fromP2) {
    if (!ZK::RDL::verify("RDL", GlobalContext::G2(), fromP2.X2, fromP2.pi2_DL)) {
        throw std::runtime_error("[Party1] Round3: RDL verify (P2) failed.");
    }
    vrf_ = ecvrf_p256_rfc9381();
    if (!vrf_) throw std::runtime_error("[Party1] ECVRF suite init failed");
    ec_group_ = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    vrf_pub_ = EC_POINT_dup(fromP2.vrf_pub, ec_group_);

    Mpz rho1 = rng_.random_mpz(C_.encrypt_randomness_bound());
    Mpz x1_mpz; utils::fr_to_mpz(x1_mpz, x1_);
    // auto ek   = C_.keygen(dk_);
    CL_HSMqk::ClearText clearX1(C_, x1_mpz);
    CL_HSMqk::CipherText ct_x1(C_, *ek_, clearX1, rho1);

    // === 保存自己的 Enc(x1)，用于签名阶段 ===
    ct_x1_self_.reset(new CL_HSMqk::CipherText(ct_x1));

    ZK::RDL_Proof   pi1_DL   = ZK::RDL::prove("RDL", GlobalContext::G2(), X1_, x1_);
    ZK::RCLDL_Proof pi1_CLDL = ZK::RCLDL::prove("RCLDL", GlobalContext::G2(), X1_, x1_, C_, *ek_, dk_mpz_, ct_x1);

    // 4) send to P2
    MsgBundle_P1toP2 out(X1_, pi1_DL, *ek_, ct_x1, pi1_CLDL);

    X2_=fromP2.X2;
    mcl::bn::G2::add(X_, X1_, X2_);
    // std::cout << "[Party1] finalize: joint public key X generated.\n";
    // std::cout << "[Party1] Round3: sent (X1, pi1_DL, ek, Enc(x1), pi1_CLDL).\n";
    
    return out;
}

void Party1::setMessages(const std::vector<mcl::bn::Fr>& msgs) {
    if (msgs.size() != GlobalContext::H().size() - 1) {
        throw std::runtime_error("[Party1] Message length mismatch with bbs_ell");
    }
    messages_ = msgs;
}


MsgSign_P1toP2 Party1::sign_pass1() {
    MsgSign_P1toP2 out;
    RAND_bytes(out.beta1.data(), out.beta1.size());
    beta1_ = out.beta1;
    // std::cout << "[Party1] Sign_Pass1: sent beta1.\n";
    return out;
}

void Party1::sign_output(const MsgSign_P2toP1 &fromP2) {
    // === Step1: Verify VRF proof ===
    // === Step0: Compute msg_hash from stored messages ===
    unsigned char msg_hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    for (auto &m : messages_) {
        std::string s = m.getStr(16);
        SHA256_Update(&ctx, s.data(), s.size());
    }
    SHA256_Final(msg_hash, &ctx);

    const unsigned char *vrf_input = msg_hash;
    size_t vrf_input_len = sizeof(msg_hash);

    if (!ECVRF_verify_rfc9381(vrf_, vrf_pub_, vrf_input, vrf_input_len,
                              fromP2.vrf_proof.data(), fromP2.vrf_proof.size())) {
        throw std::runtime_error("[Party1] Sign_Output: VRF verify failed!");
    }

    // === Step2: β₂ ← proof-to-hash ===
    unsigned char beta2[32];
    ECVRF_proof_to_hash_rfc9381(vrf_, fromP2.vrf_proof.data(),
                                fromP2.vrf_proof.size(), beta2);

    // === Step3: H3(β₁||β₂) → (e, s) ===
    std::string concat;
    concat.reserve(64);
    concat.append(reinterpret_cast<const char*>(beta1_.data()), 32);
    concat.append(reinterpret_cast<const char*>(beta2), 32);
    mcl::bn::Fr e = GlobalContext::Environment::hashToFr(concat + "e");
    mcl::bn::Fr s = GlobalContext::Environment::hashToFr(concat + "s");
    // BIGNUM *e_bn = nullptr, *s_bn = nullptr;
    // H3_beta_concat_to_scalars(vrf_->group, beta1_.data(), beta2, &e_bn, &s_bn);
    // Fr e, s;
    // e.setStr(BN_bn2hex(e_bn));
    // s.setStr(BN_bn2hex(s_bn));

    // === Step4: Compute B = G1 + sH0 + Σ miHi
    mcl::bn::G1 B;
    mcl::bn::G1 tmp,tmp2;
    G1::mul(tmp, GlobalContext::H()[0], s);
    G1::add(B, GlobalContext::G1(), tmp);
    for (size_t i = 0; i < messages_.size(); ++i) {
        G1::mul(tmp2, GlobalContext::H()[i + 1], messages_[i]);
        G1::add(B, B, tmp2);
    }


    // === Step5: Verify π_CLLIN ===
    if (!ZK::RCLLIN::verify("RCLLIN", B, GlobalContext::H()[1],
                            GlobalContext::G2(), C_, *ek_,
                            *ct_x1_self_, fromP2.CTb, fromP2.R, X2_, e, fromP2.pi_CLLin)) {
        throw std::runtime_error("[Party1] Sign_Output: RCLLIN verify failed!");
    }

    // === Step6: Decrypt CTb ===
    // CL_HSMqk::ClearText dec_CTb = C_.decrypt(dk_, fromP2.CTb);
    CL_HSMqk::ClearText dec_CTb = decrypt_CT(fromP2.CTb);
    Fr dec_fr;
    utils::mpz_to_fr(dec_fr, dec_CTb);

    // === Step7: Compute A = R / dec_fr
    mcl::bn::G1 A;
    Fr inv;
    Fr::inv(inv, dec_fr);
    G1::mul(A, fromP2.R, inv);

    // === Step8: Verify e(A, X+eG2) = e(B, G2)
    mcl::bn::G2 Xe;
    mcl::bn::G2::mul(Xe, GlobalContext::G2(), e);
    mcl::bn::G2::add(Xe, Xe, X_);

    // pairing outputs live in GT
    mcl::bn::GT left, right;

    // compute pairings
    mcl::bn::pairing(left, A, Xe);
    mcl::bn::pairing(right, B, GlobalContext::G2());

    if (left == right) {
        // === save Signature ===
        BBS_Plus_signature.reset(new BBS_Plus_Signature{});
        BBS_Plus_signature->A = A;
        BBS_Plus_signature->e = e;
        BBS_Plus_signature->s = s;
    } else {
        throw std::runtime_error("[Party1] Signature verification failed!");
    }
}