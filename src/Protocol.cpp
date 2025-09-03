//
// Created by qsang on 24-10-12.
//
#include <cmath>
#include <set>
#include <vector>
#include <numeric>
#include "../include/Protocol.h"

Protocol::Protocol(GroupParams& params) : params(params), sig_public_key(OpenSSL::ECPoint(params.ec_group))
{
    S.reserve(params.n);
}

void Protocol::dkg()
{
    RandGen randgen;

    const CL_HSMqk& cl_pp = params.cl_pp;
    const OpenSSL::ECGroup& ec_group = params.ec_group;
    const size_t n = params.n;
    const size_t t = params.t;
    const Mpz& delta = params.delta;

    // Calculate coefficient bound
    Mpz coff_bound;
    size_t ell = cl_pp.secretkey_bound().nbits() - 124; // Bound from n = 20 and t = 19

    Mpz::mulby2k(coff_bound, Mpz("1"), ell);
    std::cout << "Coefficient bound: " << coff_bound << std::endl;
    std::cout << "Secret key bound: " << cl_pp.secretkey_bound() << std::endl;

    // Initialize vectors
    std::vector<CL_HSMqk::SecretKey> sk_list;
    std::vector<Mpz> sk_list_mpz;
    std::vector<CL_HSMqk::PublicKey> pk_list;
    sk_list.reserve(n);
    sk_list_mpz.reserve(n);
    pk_list.reserve(n);

    Mpz alpha(randgen.random_mpz(coff_bound));
    Mpz cl_u, sk;
    Mpz::mul(cl_u, alpha, delta);
    Mpz::mul(sk, cl_u, delta);

    CL_HSMqk::SecretKey sk_delta(cl_pp, sk);
    CL_HSMqk::PublicKey pk = cl_pp.keygen(sk_delta);

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
        sk_list.emplace_back(cl_pp, skj);
        pk_list.emplace_back(cl_pp, sk_list.back());
    }

    // Verify CL
    Mpz cl_ut(0UL);
    std::set<size_t> SS = select_parties(randgen, n, t);
    for (size_t s : SS) {
        Mpz cl_l = cl_lagrange_at_zero(SS, s, delta);
        Mpz::mul(cl_l, cl_l, sk_list_mpz[s-1]);
        Mpz::add(cl_ut, cl_ut, cl_l);
    }
    std::cout << (sk == cl_ut ? "CL verify success" : "CL verify failed") << std::endl;

    // For ECDSA DKG
    std::vector<OpenSSL::BN> xi_list(n);
    OpenSSL::BN u(ec_group.random_mod_order());
    OpenSSL::ECPoint X(ec_group, u);

    std::vector<OpenSSL::BN> coefficient;
    std::vector<OpenSSL::ECPoint> coefficient_group;
    coefficient.reserve(t);
    coefficient_group.reserve(t);

    for (size_t k = 0; k < t; ++k) {
        coefficient.push_back(ec_group.random_mod_order());
        coefficient_group.emplace_back(ec_group, coefficient.back());
    }

    for (size_t j = 0; j < n; ++j) {
        xi_list[j] = coefficient[t-1];
        for (size_t k = t-1; k > 0; --k) {
            ec_group.mul_by_word_mod_order(xi_list[j], j+1);
            ec_group.add_mod_order(xi_list[j], xi_list[j], coefficient[k-1]);
        }
        ec_group.mul_by_word_mod_order(xi_list[j], j+1);
        ec_group.add_mod_order(xi_list[j], xi_list[j], u);
    }

    std::vector<OpenSSL::ECPoint> Xi_list;
    Xi_list.reserve(n);
    OpenSSL::ECPoint T(ec_group);
    for (const auto& xi : xi_list) {
        ec_group.scal_mul_gen(T, xi);
        Xi_list.emplace_back(ec_group, T);
    }


    OpenSSL::BN ut(0UL);
    for (size_t s : SS) {
        OpenSSL::BN l = lagrange_at_zero(ec_group, SS, s);
        ec_group.mul_mod_order(l, l, xi_list[s-1]);
        ec_group.add_mod_order(ut, ut, l);
    }
    std::cout << (u == ut ? "ECDSA verify success" : "ECDSA verify failed") << std::endl;

    // Initialize parties
    for(size_t i = 0; i < n; ++i) {
        S.emplace_back(params, i+1, pk, pk_list, sk_list[i], X, Xi_list, xi_list[i]);
    }

    sig_public_key = OpenSSL::ECPoint(ec_group, X);
}

std::vector<Signature> Protocol::run(const std::set<size_t>& party_set, const std::vector<unsigned char>& message) {
    for(auto& party : S)
    {
        party.setPartySet(party_set);
    }

    std::vector<RoundOneData> data_set_for_one;
    std::vector<RoundTwoData> data_set_for_two;
    std::vector<RoundThreeData> data_set_for_three;
    std::vector<Signature> data_set_for_offline;

    data_set_for_one.reserve(party_set.size());
    data_set_for_two.reserve(party_set.size());
    data_set_for_three.reserve(party_set.size());
    data_set_for_offline.reserve(party_set.size());

    // Execute Round 1
    for(auto& i : party_set) {
        S[i-1].handleRoundOne();
        data_set_for_one.push_back(S[i-1].getRoundOneData());
    }

    // Execute Round 2
    for(auto& i : party_set) {
        S[i-1].handleRoundTwo(data_set_for_one);
        data_set_for_two.push_back(S[i-1].getRoundTwoData());
    }

    // Execute Round 3
    for(auto& i : party_set){
        S[i-1].handleRoundThree(data_set_for_two, message);
        data_set_for_three.push_back(S[i-1].getRoundThreeData());
    }

    // Execute Offline
    for(auto& i : party_set){
        S[i-1].handleOffline(data_set_for_three);
        data_set_for_offline.push_back(S[i-1].getSignature());
    }

    return data_set_for_offline;
}

bool Protocol::verify(const std::vector<Signature>& ecdsa_sig, const std::vector<unsigned char>& message) const
{
    // Verify signatures
    OpenSSL::BN h (params.H(message));
    OpenSSL::BN inv_s;
    OpenSSL::BN u1, u2;
    OpenSSL::ECPoint R (params.ec_group);

    bool flag = true;
    for(const auto& signature : ecdsa_sig)
    {
        params.ec_group.inverse_mod_order(inv_s, signature.s);
        params.ec_group.mul_mod_order (u1, inv_s, h);
        params.ec_group.mul_mod_order (u2, inv_s, signature.rx);
        params.ec_group.scal_mul(R, u1, u2, sig_public_key);

        OpenSSL::BN rx;
        params.ec_group.x_coord_of_point (rx, R);
        params.ec_group.mod_order (rx, rx);
        flag &= (rx == signature.rx);
    }
    return flag;
}