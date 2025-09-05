//
// Created by qsang on 24-10-12.
//
#include <cmath>
#include <set>
#include <vector>
#include "../include/Protocol.h"

Protocol::Protocol(ProtocolParams& params) : params(params)
{
    S.reserve(params.n);
}

void Protocol::dkg()
{
    RandGen randgen;

    const CL_HSMqk& cl_pp = params.cl_pp;
    const size_t n = params.n;
    const size_t t = params.t;
    const size_t bbs_ell = params.ell;
    const Mpz& delta = params.delta;
    const mcl::G1& g1 = params.g1;
    const mcl::G2& g2 = params.g2;

    Mpz coff_bound;
    size_t ell = cl_pp.secretkey_bound().nbits() - 124; // Bound from n = 20 and t = 19

    Mpz::mulby2k(coff_bound, Mpz("1"), ell);
    std::cout << "Coefficient bound: " << coff_bound << std::endl;
    std::cout << "Secret key bound: " << cl_pp.secretkey_bound() << std::endl;

    // Initialize vectors
    std::vector<CL_HSMqk::SecretKey> cl_sk_list;
    std::vector<Mpz> sk_list_mpz;
    std::vector<CL_HSMqk::PublicKey> cl_pk_list;
    cl_sk_list.reserve(n);
    sk_list_mpz.reserve(n);
    cl_pk_list.reserve(n);

    Mpz alpha(randgen.random_mpz(coff_bound));
    Mpz cl_u, cl_sk;
    Mpz::mul(cl_u, alpha, delta);
    Mpz::mul(cl_sk, cl_u, delta);

    CL_HSMqk::SecretKey cl_sk_delta(cl_pp, cl_sk);
    CL_HSMqk::PublicKey cl_pk = cl_pp.keygen(cl_sk_delta);

    std::vector<Mpz> cl_coefficient;
    cl_coefficient.reserve(t);
    for (size_t k = 0; k < t; ++k) {
        cl_coefficient.emplace_back(randgen.random_mpz(coff_bound));
    }

    // Shamir Secret Sharing
    for (size_t j = 0; j < n; ++j) {
        Mpz skj = cl_coefficient[t-1];
        for (size_t k = t-1; k > 0; --k) {
            Mpz::mul(skj, skj, Mpz(j+1));
            Mpz::add(skj, skj, cl_coefficient[k-1]);
        }
        Mpz::mul(skj, skj, Mpz(j+1));
        Mpz::add(skj, skj, cl_u);
        sk_list_mpz.push_back(skj);
        cl_sk_list.emplace_back(cl_pp, skj);
        cl_pk_list.emplace_back(cl_pp, cl_sk_list.back());
    }

    // Verify CL
    Mpz cl_ut(0UL);
    std::set<size_t> SS = utils::select_parties(randgen, n, t);
    for (size_t s : SS) {
        Mpz cl_l = utils::cl_lagrange_at_zero(SS, s, delta);
        Mpz::mul(cl_l, cl_l, sk_list_mpz[s-1]);
        Mpz::add(cl_ut, cl_ut, cl_l);
    }
    std::cout << (cl_sk == cl_ut ? "CL verify success" : "CL verify failed") << std::endl;

    // For BBS+ DKG
    mcl::Fr bbs_master_sk;
    mcl::G2 bbs_master_pk;
    std::vector<mcl::Fr> bbs_sk_list;
    std::vector<mcl::G2> bbs_pk_list;
    bbs_sk_list.reserve(n);
    bbs_pk_list.reserve(n);

    bbs_master_sk.setByCSPRNG();
    std::cout << "bbs_master_sk:" << bbs_master_sk << std::endl;
    mcl::G2::mul(bbs_master_pk, g2, bbs_master_sk);

    std::vector<mcl::Fr> bbs_coeffs(t);
    bbs_coeffs.resize(t);

    for(size_t k = 0; k < t; ++k) {
        bbs_coeffs[k].setByCSPRNG();
    }

    for(size_t j = 0; j < n; ++j) {
        mcl::Fr share  = bbs_coeffs[t-1];
        for(size_t k = t-1; k > 0; --k) {
           share *= (j + 1);
           share += bbs_coeffs[k-1];
        }
        share *= (j + 1);
        share += bbs_master_sk;
        bbs_sk_list.push_back(share);
    }

    for (const mcl::Fr& sk_share : bbs_sk_list) {
        mcl::G2 pk_share;
        mcl::G2::mul(pk_share, g2, sk_share);
        bbs_pk_list.push_back(pk_share);
    }

    // Verify BBS
    mcl::Fr bbs_ut = 0;
    std::set<size_t> bbs_ss = utils::select_parties(randgen, n, t);
    for (size_t s : bbs_ss) {
        mcl::Fr bbs_l = utils::lagrange_at_zero(bbs_ss, s);
        mcl::Fr::mul(bbs_l, bbs_l, bbs_sk_list[s-1]);
        mcl::Fr::add(bbs_ut, bbs_ut, bbs_l);
    }
    std::cout << (bbs_master_sk ==bbs_ut ? "BBS verify success" : "BBS verify failed") << std::endl;

    // For Elgamal DKG
    mcl::Fr elg_master_sk;
    mcl::G1 elg_master_pk;
    std::vector<mcl::Fr> elg_sk_list;
    std::vector<mcl::G1> elg_pk_list;
    elg_sk_list.reserve(n);
    elg_pk_list.reserve(n);

    elg_master_sk.setByCSPRNG();
    mcl::G1::mul(elg_master_pk, g1, elg_master_sk);

    std::vector<mcl::Fr> elg_coeffs(t);
    elg_coeffs.resize(t);

    for(size_t k = 0; k < t; ++k) {
        elg_coeffs[k].setByCSPRNG();
    }

    for(size_t j = 0; j < n; ++j) {
        mcl::Fr share  = elg_coeffs[t-1];
        for(size_t k = t-1; k > 0; --k) {
            share *= (j + 1);
            share += elg_coeffs[k-1];
        }
        share *= (j + 1);
        share += elg_master_sk;
        elg_sk_list.push_back(share);
    }

    for (const mcl::Fr& sk_share : elg_sk_list) {
        mcl::G1 pk_share;
        mcl::G1::mul(pk_share, g1, sk_share);
        elg_pk_list.push_back(pk_share);
    }

    // Verify Elgamal
    mcl::Fr elg_ut = 0;
    std::set<size_t> elg_ss = utils::select_parties(randgen, n, t);
    for (size_t s : elg_ss) {
        mcl::Fr elg_l = utils::lagrange_at_zero(elg_ss, s);
        mcl::Fr::mul(elg_l, elg_l, elg_sk_list[s-1]);
        mcl::Fr::add(elg_ut, elg_ut, elg_l);
    }
    std::cout << (elg_master_sk == elg_ut ? "Elg verify success" : "Elg verify failed") << std::endl;

    std::vector<mcl::G1> bbs_H(bbs_ell+1);
    for (size_t i =0; i < bbs_ell+1; ++i) {
        mcl::Fr tmp;
        tmp.setByCSPRNG();
        mcl::G1::mul(bbs_H[i], g1, tmp);
    }

    Mpz r(randgen.random_mpz(cl_pp.encrypt_randomness_bound()));
    Mpz bbs_master_sk_mpz, bbs_master_sk_mpz_recover;
    utils::fr_to_mpz(bbs_master_sk_mpz, bbs_master_sk);
    CL_HSMqk::ClearText ct (cl_pp, bbs_master_sk_mpz);
    CL_HSMqk::CipherText ct_cl_sk = cl_pp.encrypt(cl_pk, ct, r);

    // Initialize parties
    for(size_t i = 0; i < n; ++i) {
        S.emplace_back(params, i + 1, cl_pk, cl_pk_list, cl_sk_list[i], ct_cl_sk, bbs_master_pk, bbs_pk_list, bbs_H,
                       bbs_sk_list[i], elg_master_pk, elg_pk_list, elg_sk_list[i]);
    }

    sig_public_key_g2 = bbs_master_pk;
    sig_public_key_g1 = bbs_H;

}

std::vector<Signature> Protocol::run(const std::set<size_t>& party_set, const std::vector<mcl::Fr>& message) {
    for(auto& party : S)
    {
        party.setPartySet(party_set);
    }

    std::vector<RoundOneData> data_set_for_one;
    std::vector<RoundTwoData> data_set_for_two;
    std::vector<Signature> data_set_for_offline;

    data_set_for_one.reserve(party_set.size());
    data_set_for_two.reserve(party_set.size());

    data_set_for_offline.reserve(party_set.size());

    // Execute Round 1
    for(auto& i : party_set) {
        S[i-1].handleRoundOne(message);
        data_set_for_one.push_back(S[i-1].getRoundOneData());
    }

    // Execute Round 2
    for(auto& i : party_set) {
        S[i-1].handleRoundTwo(data_set_for_one);
        data_set_for_two.push_back(S[i-1].getRoundTwoData());
    }

    // Execute Offline
    for(auto& i : party_set){
        S[i-1].handleOffline(data_set_for_two);
        data_set_for_offline.push_back(S[i-1].getSignature());
    }

    return data_set_for_offline;
}

bool Protocol::verify(const std::vector<Signature>& bbs_signatures, const std::vector<mcl::Fr>& message) const
{
    bool flag = true;
    for(const auto& signature : bbs_signatures)
    {
        mcl::GT pairing_left, pairing_right;
        mcl::G2 B_left;
        mcl::G2::mul(B_left, params.g2, signature.e);
        mcl::G2::add(B_left, B_left, sig_public_key_g2);
        mcl::pairing(pairing_left, signature.A, B_left);

        mcl::G1 A_right;
        mcl::G1::mul(A_right, sig_public_key_g1[0], signature.s);

        for (size_t i = 0; i < message.size(); i++) {
            mcl::G1 term;
            mcl::G1::mul(term, sig_public_key_g1[i+1], message[i]);
            mcl::G1::add(A_right, A_right, term);
        }

        mcl::G1::add(A_right, A_right, params.g1);
        mcl::pairing(pairing_right, A_right, params.g2);

        flag &= (pairing_left == pairing_right);
    }
    return flag;
}