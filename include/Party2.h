#pragma once
#include <memory>
#include <vector>
#include <mcl/bls12_381.hpp>
#include "Messages.h"
#include "zk_sigma.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/bn.h>

using namespace mcl::bn;

class Party2 {
public:
    Party2();
    ~Party2();
    MsgBundle_P2toP1 round2(const MsgCommit_P1toP2& fromP1);
    mcl::bn::G2 finalize(const MsgBundle_P1toP2& fromP1, const MsgCommit_P1toP2& com1_from_round1);
    const CL_HSMqk& C() const { return C_; }
    mcl::bn::G2 X1_;
    mcl::bn::G2 X2_;
    mcl::bn::G2 X_;
    ecvrf_suite* vrf_{nullptr};
    EC_KEY* ec_key_ = nullptr; 
    EC_POINT* vrf_pub_{nullptr};  
    // PublicKey、CipherText 无默认构造 ⇒ 用指针延迟构造
    std::unique_ptr<BICYCL::CL_HSMqk::PublicKey> ek_from_P1_;
    std::unique_ptr<BICYCL::CL_HSMqk::CipherText> ct_x1_from_P1_;

    std::vector<mcl::bn::Fr> messages_;
    void setMessages(const std::vector<mcl::bn::Fr>& msgs);

    MsgSign_P2toP1 sign_pass2(const MsgSign_P1toP2 &fromP1);

private:
    BICYCL::RandGen rng_;
    BICYCL::CL_HSMqk C_;
    mcl::bn::Fr x2_;
    BIGNUM* priv_ = nullptr;
};
