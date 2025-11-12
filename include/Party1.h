#pragma once
#include <memory>
#include <vector>
#include <mcl/bls12_381.hpp>
#include "bicycl/bicycl.hpp"
#include "bicycl/CL_HSMqk.hpp"
#include "Messages.h"
#include "zk_sigma.h"

using namespace mcl::bn;
using namespace BICYCL;

class Party1 {
public:
    Party1();
    ~Party1();
    MsgCommit_P1toP2 round1();
    MsgBundle_P1toP2 round3(const MsgBundle_P2toP1& fromP2); 
    const CL_HSMqk& C() const { return C_; }
    std::unique_ptr<BICYCL::CL_HSMqk::PublicKey> ek_;
    mcl::bn::G2 X1_;
    mcl::bn::G2 X2_;
    mcl::bn::G2 X_;
    std::vector<uint8_t> com1_cached_;
    EC_KEY* ec_key_ = nullptr;
    ecvrf_suite* vrf_{nullptr};
    EC_GROUP* ec_group_{nullptr};
    EC_POINT* vrf_pub_{nullptr};
    std::unique_ptr<BICYCL::CL_HSMqk::CipherText> ct_x1_self_;

    std::vector<mcl::bn::Fr> messages_;
    void setMessages(const std::vector<mcl::bn::Fr>& msgs);

    std::array<unsigned char, 32> beta1_;
    MsgSign_P1toP2 sign_pass1();   
    void sign_output(const MsgSign_P2toP1 &fromP2);

    BICYCL::CL_HSMqk::ClearText decrypt_CT(const BICYCL::CL_HSMqk::CipherText& ct) const;

    std::unique_ptr<BBS_Plus_Signature> BBS_Plus_signature;

private:
    BICYCL::RandGen rng_;
    BICYCL::CL_HSMqk C_;
    Mpz dk_mpz_;
    std::unique_ptr<BICYCL::CL_HSMqk::SecretKey> dk_;
    mcl::bn::Fr x1_;
};


