//
// Created by qsang on 05/09/25.
//

#ifndef PROTOCOL_TYPES_H
#define PROTOCOL_TYPES_H

#include <mcl/bls12_381.hpp>
#include "threshold_elgamal.h"
#include "bicycl/bicycl.hpp"

// Data structures for different rounds of the protocol.
struct RoundOneData {
    size_t id;
    mcl::G1 m0_share, m1_share;
    CL_HSMqk::CipherText c_gamma_share, c_gamma_x_share;
    ThresholdElgamal<mcl::G1>::CipherText c_d0_share, c_d1_share;

    RoundOneData(const size_t id, const mcl::G1& m0_share, const mcl::G1& m1_share,
    const CL_HSMqk::CipherText& c_gamma_share, const CL_HSMqk::CipherText& c_gamma_x_share,
    const ThresholdElgamal<mcl::G1>::CipherText& c_d0_share, ThresholdElgamal<mcl::G1>::CipherText& c_d1_share) : id(id), m0_share(m0_share), m1_share(m1_share), c_gamma_share(c_gamma_share), c_gamma_x_share(c_gamma_x_share), c_d0_share(c_d0_share), c_d1_share(c_d1_share)
    {}
};

struct RoundTwoData {
    size_t id;
    QFI part_c0_dec_share;
    mcl::G1 part_c1_dec_share;

    RoundTwoData(const size_t id, const QFI& part_c0_dec_share, const mcl::G1& part_c1_dec_share)
        : id(id), part_c0_dec_share(part_c0_dec_share), part_c1_dec_share(part_c1_dec_share) {}
};


struct RoundTwoLocalData {
    size_t id;
    CL_HSMqk::CipherText cl_c;
    ThresholdElgamal<mcl::G1>::CipherText c_sd0_d1;
    mcl::Fr e, s;

    RoundTwoLocalData(const size_t id, const CL_HSMqk::CipherText& cl_c, const ThresholdElgamal<mcl::G1>::CipherText& c_sd0_d1, mcl::Fr& e, mcl::Fr& s)
        : id(id), cl_c(cl_c), c_sd0_d1(c_sd0_d1), e(e), s(s) {}
};

struct Signature {
    mcl::G1 A;
    mcl::Fr e;
    mcl::Fr s;

    Signature(const mcl::G1& A, const mcl::Fr& e, const mcl::Fr& s) : A(A), e(e), s(s) {}
};

// Class holding group parameters for the protocol.
class ProtocolParams {
public:
    SecLevel sec_level;
    size_t n;
    size_t t;
    size_t ell;

    Mpz delta;
    OpenSSL::HashAlgo H;
    CL_HSMqk cl_pp;

    mcl::G1 g1;
    mcl::G2 g2;

    ProtocolParams(mcl::CurveParam cp, SecLevel seclevel, size_t n, size_t t, size_t ell, RandGen& randgen)
    : sec_level(seclevel), n(n), t(t), ell(ell), delta(utils::factorial(n)), H(seclevel), cl_pp(Mpz("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"), 1, seclevel, randgen) {
        initPairing(cp);
        mcl::hashAndMapToG1(g1, "1");
        mcl::hashAndMapToG2(g2, "1");
    }
};

#endif //PROTOCOL_TYPES_H
