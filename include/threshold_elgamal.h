#pragma once

#include "Utils.h"
#include<optional>
#include <mcl/bls12_381.hpp>
#include <set>
#include <unordered_map>

template<typename Ec>
class ThresholdElgamal {
public:
    struct CipherText {
        Ec c1;
        Ec c2;
    };

    ThresholdElgamal(const Ec& g, const Ec& pk, const mcl::Fr& sk_share)
        : g_(g), pk_(pk), sk_share_(sk_share) {}

    ThresholdElgamal(const Ec& g, const Ec& pk)
        : g_(g), pk_(pk) {
        sk_share_.setStr("0");
    }

    const Ec& getGenerator() const {
        return g_;
    }

    const Ec& getPublicKey() const {
        return pk_;
    }

    const mcl::Fr& getSecretKeyShare() const {
        return sk_share_;
    }

    void encrypt(CipherText& cipher, const Ec& M, const mcl::Fr& r) const {
        Ec::mul(cipher.c1, g_, r);
        Ec::mul(cipher.c2, pk_, r);
        Ec::add(cipher.c2, cipher.c2, M);
    }

    void partial_decrypt(Ec& share, const CipherText& cipher) const {
        Ec::mul(share, cipher.c1, sk_share_);
    }

    static void combine(Ec& M, const CipherText& cipher, const std::unordered_map<size_t, Ec>& shares) {
        std::set<size_t> S;
        for(const auto& share : shares) {
            S.insert(share.first);
        }

        Ec sum;
        sum.clear();

        for(const auto& share : shares) {
            mcl::Fr lambda = utils::lagrange_at_zero(S, share.first);
            Ec temp;
            Ec::mul(temp, share.second, lambda);
            Ec::add(sum, sum, temp);
        }

        Ec::sub(M, cipher.c2, sum);
    }

    static void add(CipherText& result, const CipherText& c1, const CipherText& c2) {
        Ec::add(result.c1, c1.c1, c2.c1);
        Ec::add(result.c2, c1.c2, c2.c2);
    }

    static void scalar_mul(CipherText& result, const CipherText& c, const mcl::Fr& scalar) {
        Ec::mul(result.c1, c.c1, scalar);
        Ec::mul(result.c2, c.c2, scalar);
    }

private:
    Ec g_;
    Ec pk_;
    mcl::Fr sk_share_;
};

template<typename Ec>
class Elgamal_Part_Dec_ZKProof
{
public:
    Elgamal_Part_Dec_ZKProof(const ThresholdElgamal<Ec> &threshold_elgamal,
                             const typename ThresholdElgamal<Ec>::CipherText &c,
                             const Ec &pd) {
        const Ec& g = threshold_elgamal.getGenerator();
        const mcl::Fr& sk_share = threshold_elgamal.getSecretKeyShare();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr r;
        r.setByCSPRNG();

        Ec::mul(t1_, g, r);
        Ec::mul(t2_, c.c1, r);

        k_ = k_from_hash(pk, c, pd, t1_, t2_);

        mcl::Fr::mul(z_, k_, sk_share);
        mcl::Fr::add(z_, z_, r);

    }

    bool verify(const ThresholdElgamal<Ec> &threshold_elgamal, Ec& pk_share, const typename ThresholdElgamal<Ec>::CipherText &c,
                const Ec &pd) const {

        const Ec& g = threshold_elgamal.getGenerator();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr k_prime = k_from_hash(pk, c, pd, t1_, t2_);

        Ec eql, eqr, tmp;

        Ec::mul(eql, g, z_);
        Ec::mul(tmp, pk_share, k_prime);
        Ec::add(eqr, tmp, t1_);

        if (eql != eqr) return false;

        Ec::mul(eql, c.c1, z_);
        Ec::mul(tmp, pd, k_prime);
        Ec::add(eqr, tmp, t2_);

        return (eql == eqr);
    }

private:
    mcl::Fr k_from_hash(const Ec &pk,
                         const typename ThresholdElgamal<Ec>::CipherText &c,
                         const Ec &pd,
                         const Ec &t1, const Ec &t2) const {

        std::ostringstream os;
        os << pk << c.c1 << c.c2 << pd << t1 << t2;
        mcl::Fr k;
        k.setHashOf(os.str());
        return k;
    }

    Ec t1_, t2_;
    mcl::Fr k_;
    mcl::Fr z_;
};

template<typename Ec>
class Elgamal_CL_Consistency_ZKProof
{
public:
    Elgamal_CL_Consistency_ZKProof(const CL_HSMqk &C, OpenSSL::HashAlgo &H,
                                   const CL_HSMqk::PublicKey &cl_pk,
                                   const CL_HSMqk::CipherText &ct_bbs_sk,
                                   RandGen &randgen,
                                   const ThresholdElgamal<Ec> &threshold_elgamal,
                                   const Ec &H0, const Ec &D,
                                   const mcl::Fr& gamma_share, const mcl::Fr& alpha_1, mcl::Fr& alpha_2,
                                   const Mpz &beta_1, const Mpz &beta_2,
                                   const CL_HSMqk::CipherText &c_gamma_share,
                                   const CL_HSMqk::CipherText &c_gamma_x_share,
                                   typename ThresholdElgamal<Ec>::CipherText& c_d0_share,
                                   typename ThresholdElgamal<Ec>::CipherText& c_d1_share)
            : t_gamma(C.encrypt(cl_pk, CL_HSMqk::ClearText(C, Mpz("0")), Mpz("0"))),
              t_m(C.encrypt(cl_pk, CL_HSMqk::ClearText(C, Mpz("0")), Mpz("0"))){

        const Ec& g = threshold_elgamal.getGenerator();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr alpha_prime_1, alpha_prime_2, gamma_prime;
        alpha_prime_1.setByCSPRNG();
        alpha_prime_2.setByCSPRNG();
        gamma_prime.setByCSPRNG();

        Ec tmp;
        Ec::mul(t01, g, alpha_prime_1);
        Ec::mul(t11, g, alpha_prime_2);

        Ec::mul(tmp, pk, alpha_prime_1);
        Ec::mul(t02, H0, gamma_prime);
        Ec::add(t02, t02, tmp);

        Ec::mul(tmp, pk, alpha_prime_2);
        Ec::mul(t12, D, gamma_prime);
        Ec::add(t12, t12, tmp);

        int soundness = H.digest_nbits();

        Mpz B (C.encrypt_randomness_bound());
        Mpz::mulby2k (B, B, soundness);
        Mpz::mulby2k (B, B, C.lambda_distance());

        Mpz beta_prime_1 (randgen.random_mpz (B));
        Mpz beta_prime_2 (randgen.random_mpz (B));

        Mpz gamma_prime_mpz;
        utils::fr_to_mpz(gamma_prime_mpz, gamma_prime);

        t_gamma = CL_HSMqk::CipherText(C, cl_pk, CL_HSMqk::ClearText (C, gamma_prime_mpz), beta_prime_1);;

        CL_HSMqk::CipherText t1 (C.scal_ciphertexts(cl_pk, ct_bbs_sk, gamma_prime_mpz, Mpz("0")));
        CL_HSMqk::CipherText t2 (C, cl_pk, CL_HSMqk::ClearText (C, Mpz("0")), beta_prime_2);
        t_m = CL_HSMqk::CipherText (C.add_ciphertexts(cl_pk, t1, t2, Mpz("0")));

        k_ = k_from_hash(cl_pk, pk, H0, D, ct_bbs_sk, c_gamma_share, c_gamma_x_share, c_d0_share, c_d1_share);

        Mpz k_mpz, gamma_share_mpz;
        utils::fr_to_mpz(k_mpz, k_);
        utils::fr_to_mpz(gamma_share_mpz, gamma_share);

        Mpz::mul(z_, k_mpz, gamma_share_mpz);
        Mpz::add(z_, z_, gamma_prime_mpz);

        mcl::Fr::mul(z_fr_, k_, gamma_share);
        mcl::Fr::add(z_fr_, z_fr_, gamma_prime);

        mcl::Fr::mul(a1_, k_, alpha_1);
        mcl::Fr::add(a1_, a1_, alpha_prime_1);

        mcl::Fr::mul(a2_, k_, alpha_2);
        mcl::Fr::add(a2_, a2_, alpha_prime_2);

        Mpz::mul (b1_, k_mpz, beta_1);
        Mpz::add (b1_, b1_, beta_prime_1);

        Mpz::mul (b2_, k_mpz, beta_2);
        Mpz::add (b2_, b2_, beta_prime_2);

    }

    bool verify(const CL_HSMqk &C, OpenSSL::HashAlgo &H,
                                   const CL_HSMqk::PublicKey &cl_pk,
                                   const ThresholdElgamal<Ec> &threshold_elgamal,
                                   const Ec &H0, const Ec &D,
                                   const CL_HSMqk::CipherText &ct_bbs_sk,
                                   const CL_HSMqk::CipherText &c_gamma_share,
                                   const CL_HSMqk::CipherText &c_gamma_x_share,
                                   const typename ThresholdElgamal<Ec>::CipherText& c_d0_share,
                                   const typename ThresholdElgamal<Ec>::CipherText& c_d1_share) const {

        const Ec& g = threshold_elgamal.getGenerator();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr k_prime = k_from_hash(cl_pk, pk, H0, D, ct_bbs_sk, c_gamma_share, c_gamma_x_share, c_d0_share, c_d1_share);

        Ec eql_ec, eqr_ec;
        Ec::mul(eql_ec, g, a1_);
        Ec::mul(eqr_ec, c_d0_share.c1, k_prime);
        Ec::add(eqr_ec, eqr_ec, t01);

        if (eql_ec != eqr_ec) return false;

        Ec::mul(eql_ec, g, a2_);
        Ec::mul(eqr_ec, c_d1_share.c1, k_prime);
        Ec::add(eqr_ec, eqr_ec, t11);

        if (eql_ec != eqr_ec) return false;

        Ec tmp;
        Ec::mul(eql_ec, H0, z_fr_);
        Ec::mul(tmp, pk, a1_);
        Ec::add(eql_ec, eql_ec, tmp);
        Ec::mul(eqr_ec, c_d0_share.c2, k_prime);
        Ec::add(eqr_ec, eqr_ec, t02);

        if (eql_ec != eqr_ec) return false;

        Ec::mul(eql_ec, D, z_fr_);
        Ec::mul(tmp, pk, a2_);
        Ec::add(eql_ec, eql_ec, tmp);
        Ec::mul(eqr_ec, c_d1_share.c2, k_prime);
        Ec::add(eqr_ec, eqr_ec, t12);

        if (eql_ec != eqr_ec) return false;

        QFI eqr_c1_qfi, eqr_c2_qfi;
        Mpz z_fr_mpz;
        utils::fr_to_mpz(z_fr_mpz, z_fr_);
        CL_HSMqk::CipherText t (C, cl_pk, CL_HSMqk::ClearText (C, z_fr_mpz), b1_);

        Mpz k_mpz;
        utils::fr_to_mpz(k_mpz, k_prime);
        C.Cl_G().nupow(eqr_c1_qfi, c_gamma_share.c1(), k_mpz);
        C.Cl_G().nucomp(eqr_c1_qfi, eqr_c1_qfi, t_gamma.c1());

        if ( !(t.c1() == eqr_c1_qfi) ) return false;

        C.Cl_G().nupow(eqr_c2_qfi, c_gamma_share.c2(), k_mpz);
        C.Cl_G().nucomp(eqr_c2_qfi, eqr_c2_qfi, t_gamma.c2());

        if ( !(t.c2() == eqr_c2_qfi) ) return false;

        CL_HSMqk::CipherText tx (C.scal_ciphertexts(cl_pk, ct_bbs_sk, z_, Mpz("0")));
        CL_HSMqk::CipherText tb (C, cl_pk, CL_HSMqk::ClearText (C, Mpz("0")), b2_);
        CL_HSMqk::CipherText eql_c = C.add_ciphertexts(cl_pk, tx, tb, Mpz("0"));

        CL_HSMqk::CipherText txr (C.scal_ciphertexts(cl_pk, c_gamma_x_share, k_mpz, Mpz("0")));
        CL_HSMqk::CipherText eqr_c = C.add_ciphertexts(cl_pk, t_m, txr, Mpz("0"));

        return (eql_c.c1() == eqr_c.c1() && eql_c.c2() == eqr_c.c2());
    }

private:
    mcl::Fr k_from_hash(const CL_HSMqk::PublicKey &cl_pk,
                        const Ec &el_pk,
                        const Ec &H0, const Ec &D,
                        const CL_HSMqk::CipherText &ct_bbs_sk,
                        const CL_HSMqk::CipherText &c_gamma_share,
                        const CL_HSMqk::CipherText &c_gamma_x_share,
                        const typename ThresholdElgamal<Ec>::CipherText& c_d0_share,
                        const typename ThresholdElgamal<Ec>::CipherText& c_d1_share) const {
        std::ostringstream os;
        os << cl_pk << el_pk << H0 << D << ct_bbs_sk.c1() << ct_bbs_sk.c2() << c_gamma_share.c1() << c_gamma_share.c2()
                << c_gamma_x_share.c1() << c_gamma_x_share.c2() << c_d0_share.c1 << c_d0_share.c2 << c_d1_share.c1 <<
                c_d1_share.c2;
        mcl::Fr k; k.setHashOf(os.str());
        return k;
    }

    mcl::Fr k_;
    // com
    Ec t01, t02;
    Ec t11, t12;
    // resp
    mcl::Fr a1_, a2_;
    Mpz z_;
    mcl::Fr z_fr_;
    Mpz b1_, b2_;
    CL_HSMqk::CipherText t_gamma;
    CL_HSMqk::CipherText t_m;
};


template<typename Ec>
class Elgamal_DDH_ZKProof
{
public:
    Elgamal_DDH_ZKProof(const ThresholdElgamal<Ec> &threshold_elgamal,
                             const Ec& y, const Ec& pk_share,
                             const Ec& m_share) {
        const Ec& g = threshold_elgamal.getGenerator();
        const mcl::Fr& sk_share = threshold_elgamal.getSecretKeyShare();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr r;
        r.setByCSPRNG();

        Ec::mul(t1_, g, r);
        Ec::mul(t2_, y, r);

        mcl::Fr k = k_from_hash(pk, y, pk_share, m_share);

        mcl::Fr::mul(z_, k, sk_share);
        mcl::Fr::add(z_, z_, r);

    }

    bool verify(const ThresholdElgamal<Ec> &threshold_elgamal,
    const Ec& y, const Ec& pk_share,
    const Ec& m_share) const {

        const Ec& g = threshold_elgamal.getGenerator();
        const Ec& pk = threshold_elgamal.getPublicKey();

        mcl::Fr k_prime = k_from_hash(pk, y, pk_share, m_share);

        Ec eql, eqr, tmp;

        Ec::mul(eql, g, z_);
        Ec::mul(tmp, pk_share, k_prime);
        Ec::add(eqr, tmp, t1_);

        if (eql != eqr) return false;

        Ec::mul(eql, y, z_);
        Ec::mul(tmp, m_share, k_prime);
        Ec::add(eqr, tmp, t2_);

        return (eql == eqr);
    }

private:
    mcl::Fr k_from_hash(const Ec &pk, const Ec& y, const Ec& pk_share, const Ec& m_share) const {
        std::ostringstream os;
        os << pk << y << pk_share << m_share;
        mcl::Fr k;
        k.setHashOf(os.str());
        return k;
    }

    Ec t1_, t2_;
    mcl::Fr k_;
    mcl::Fr z_;
};