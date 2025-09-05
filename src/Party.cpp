//
// Created by qsang on 24-10-12.
//

#include "../include/Party.h"
#include "../include/threshold_elgamal.h"
#include "../include/protocol_types.h"

Party::Party(ProtocolParams& params, size_t id, const CL_HSMqk::PublicKey& cl_pk, const std::vector<CL_HSMqk::PublicKey>& cl_pk_share_vector, const CL_HSMqk::SecretKey& cl_sk_share, const CL_HSMqk::CipherText& ct_bbs_sk, const mcl::G2& bbs_pk, const std::vector<mcl::G2>& bbs_pk_share_vector, const std::vector<mcl::G1>& bbs_H, const mcl::Fr& bbs_sk_share, const mcl::G1& elg_pk, const std::vector<mcl::G1>& elg_pk_share_vector, const mcl::Fr& elg_sk_share)
: params(params), id(id), cl_pk(cl_pk), cl_pk_share_vector(cl_pk_share_vector), cl_sk_share(cl_sk_share), ct_bbs_sk(ct_bbs_sk),
bbs_pk(bbs_pk), bbs_pk_share_vector(bbs_pk_share_vector), bbs_H(bbs_H), bbs_sk_share(bbs_sk_share),
elg_pk(elg_pk), elg_pk_share_vector(elg_pk_share_vector), elg_sk_share(elg_sk_share), S()
{ }

void Party::setPartySet(const std::set<size_t>& party_set)
{
    S = party_set;
}

const RoundOneData& Party::getRoundOneData() const
{
    if (round1Data == nullptr) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    return *round1Data;
}

RoundTwoData Party::getRoundTwoData() const
{
    if (round2Data == nullptr) {
        throw std::runtime_error("Round two data is not initialized.");
    }
    return *round2Data;
}

const Signature& Party::getSignature() const
{
    if (!signature) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    return *signature;
}

void Party::handleRoundOne(const std::vector<mcl::Fr>& m)
{

    mcl::Fr sid, zero, one;
    mcl::G1 y0, y1;

    sid.setByCSPRNG();

    std::vector<mcl::Fr> data = m;
    zero.setStr("0");
    one.setStr("1");

    data.push_back(sid);
    data.push_back(zero);
    mcl::hashAndMapToG1(y0, data.data(), data.size());

    data.pop_back();
    data.push_back(one);
    mcl::hashAndMapToG1(y1, data.data(), data.size());

    mcl::G1 m0_share, m1_share;
    mcl::G1::mul(m0_share, y0, elg_sk_share);
    mcl::G1::mul(m1_share, y1, elg_sk_share);

    mcl::Fr gamma_share;
    gamma_share.setByCSPRNG();
    RandGen randgen;
    Mpz r(randgen.random_mpz(params.cl_pp.encrypt_randomness_bound()));
    Mpz gamma_share_mpz;
    utils::fr_to_mpz(gamma_share_mpz, gamma_share);
    CL_HSMqk::ClearText ct (params.cl_pp, gamma_share_mpz);
    CL_HSMqk::CipherText c_gamma_share = params.cl_pp.encrypt(cl_pk, ct, r);
    CL_HSMqk::CipherText c_gamma_x_share = params.cl_pp.scal_ciphertexts(cl_pk, ct_bbs_sk, gamma_share_mpz, Mpz("0"));

    mcl::G1 D0_share;
    mcl::G1::mul(D0_share, bbs_H[0], gamma_share);
    mcl::G1 D = params.g1;
    mcl::G1 D1_share;

    for (size_t i = 0; i < m.size(); i++) {
        mcl::G1 tmp;
        mcl::G1::mul(tmp, bbs_H[i+1], m[i]);
        mcl::G1::add(D, D, tmp);
    }

    mcl::G1::mul(D1_share, D, gamma_share);

    ThresholdElgamal<mcl::G1> elgamal(params.g1, elg_pk, elg_sk_share);

    ThresholdElgamal<mcl::G1>::CipherText c_d0_share;
    ThresholdElgamal<mcl::G1>::CipherText c_d1_share;

    mcl::Fr el_r;
    el_r.setByCSPRNG();

    elgamal.encrypt(c_d0_share, D0_share, el_r);
    elgamal.encrypt(c_d1_share, D1_share, el_r);

    round1Data = std::make_unique<RoundOneData>(id, m0_share, m1_share, c_gamma_share, c_gamma_x_share, c_d0_share,
                                                c_d1_share);
}

void Party::handleRoundTwo(std::vector<RoundOneData>& data)
{
    RandGen randgen;
    std::vector<mcl::Fr> coffs;
    for (size_t i = 0; i < data.size(); i++) {
        mcl::Fr lambda = utils::lagrange_at_zero(S, data[i].id);
        coffs.push_back(lambda);
    }

    mcl::G1 m0, m1;
    m0.clear();
    m1.clear();

    for (size_t i = 0; i < data.size(); i++) {
        mcl::G1 tmp;
        mcl::G1::mul(tmp, data[i].m0_share, coffs[i]);
        mcl::G1::add(m0, m0, tmp);
        mcl::G1::mul(tmp, data[i].m1_share, coffs[i]);
        mcl::G1::add(m1, m1, tmp);
    }

    mcl::Fr e = utils::hash_g1_to_fr(m0);
    mcl::Fr s = utils::hash_g1_to_fr(m1);

    CL_HSMqk::CipherText c_gamma = data[0].c_gamma_share;
    CL_HSMqk::CipherText c_gamma_x = data[0].c_gamma_x_share;

    ThresholdElgamal<mcl::G1> elgamal(params.g1, elg_pk, elg_sk_share);

    ThresholdElgamal<mcl::G1>::CipherText c_d0 = data[0].c_d0_share;
    ThresholdElgamal<mcl::G1>::CipherText c_d1 = data[0].c_d1_share;

    for(size_t i = 1; i < data.size(); ++i)
    {
        c_gamma = params.cl_pp.add_ciphertexts(cl_pk, c_gamma, data[i].c_gamma_share, Mpz("0"));
        c_gamma_x = params.cl_pp.add_ciphertexts(cl_pk, c_gamma_x, data[i].c_gamma_x_share, Mpz("0"));

        ThresholdElgamal<mcl::G1>::add(c_d0, c_d0, data[i].c_d0_share);
        ThresholdElgamal<mcl::G1>::add(c_d1, c_d1, data[i].c_d1_share);
    }

    Mpz e_mpz;
    utils::fr_to_mpz(e_mpz, e);
     CL_HSMqk::CipherText c_gamma_e = params.cl_pp.scal_ciphertexts(cl_pk, c_gamma, e_mpz, Mpz("0"));
     CL_HSMqk::CipherText cl_c = params.cl_pp.add_ciphertexts(cl_pk, c_gamma_e, c_gamma_x, Mpz("0"));

    ThresholdElgamal<mcl::G1>::CipherText c_sd0_d1;
    ThresholdElgamal<mcl::G1>::scalar_mul(c_d0, c_d0, s);
    ThresholdElgamal<mcl::G1>::add(c_sd0_d1, c_d1, c_d0);

    QFI part_c0_dec_share;
    mcl::G1 part_c1_dec_share;

    partial_decrypt(cl_sk_share, cl_c, part_c0_dec_share);
    elgamal.partial_decrypt(part_c1_dec_share, c_sd0_d1);

    round2Data = std::make_unique<RoundTwoData>(id, part_c0_dec_share, part_c1_dec_share);
    round2LocalData = std::make_unique<RoundTwoLocalData>(id, cl_c, c_sd0_d1, e, s);
}

    void Party::handleOffline(std::vector<RoundTwoData>& data)
{

    std::unordered_map<size_t, QFI> part_c0_dec_shares;
    std::unordered_map<size_t, mcl::G1> part_c1_dec_shares;
    part_c0_dec_shares.reserve(data.size());
    part_c1_dec_shares.reserve(data.size());

    for(size_t i = 0; i < data.size(); ++i)
    {
        part_c0_dec_shares[data[i].id] = data[i].part_c0_dec_share;
        part_c1_dec_shares[data[i].id] = data[i].part_c1_dec_share;
    }

    CL_HSMqk::ClearText m0 = agg_partial_ciphertext(part_c0_dec_shares, round2LocalData->cl_c);
    mcl::G1 m1;
    ThresholdElgamal<mcl::G1>::combine(m1, round2LocalData->c_sd0_d1, part_c1_dec_shares);

    mcl::Fr m0_fr, inv_m0_fr;
    utils::mpz_to_fr(m0_fr, m0);
    mcl::Fr::inv(inv_m0_fr, m0_fr);
    mcl::G1 A;
    mcl::G1::mul(A, m1, inv_m0_fr);

    signature = std::make_unique<Signature>(A, round2LocalData->e, round2LocalData->s);

}

bool Party::verify(const Signature& signature, const std::vector<mcl::Fr>& m) const
{
    mcl::GT pairing_left, pairing_right;
    mcl::G2 B_left;
    mcl::G2::mul(B_left, params.g2, signature.e);
    mcl::G2::add(B_left, B_left, bbs_pk);
    mcl::pairing(pairing_left, signature.A, B_left);

    mcl::G1 A_right;
    mcl::G1::mul(A_right, bbs_H[0], signature.s);

    for (size_t i = 0; i < m.size(); i++) {
        mcl::G1 term;
        mcl::G1::mul(term, bbs_H[i+1], m[i]);
        mcl::G1::add(A_right, A_right, term);
    }
    mcl::G1::add(A_right, A_right, params.g1);

    mcl::pairing(pairing_right, A_right, params.g2);

    return (pairing_left == pairing_right);
}


void Party::partial_decrypt(const CL_HSMqk::SecretKey &ski, const CL_HSMqk::CipherText &encrypted_message, QFI &part_dec)
{
    Mpz sk_mpz(ski);
    Mpz::mod(sk_mpz, sk_mpz, params.cl_pp.secretkey_bound());

    QFI fm;
    params.cl_pp.Cl_G().nupow (fm, encrypted_message.c1(), sk_mpz);
    if (params.cl_pp.compact_variant())
        params.cl_pp.from_Cl_DeltaK_to_Cl_Delta (fm);

    part_dec = fm;
}

CL_HSMqk::ClearText Party::agg_partial_ciphertext(const std::unordered_map<size_t, QFI>& pd_map, const CL_HSMqk::CipherText &c) const
{
    QFI c2 = c.c2();

    if (pd_map.size() <= params.t) {
        throw std::runtime_error("Insufficient shares for aggregation.");
    }

    for (size_t s : S)
    {
        QFI num;
        params.cl_pp.Cl_G().nupow (num, pd_map.at(s), utils::cl_lagrange_at_zero(S, s, params.delta));
        params.cl_pp.Cl_Delta().nucompinv(c2, c2, num);
    }
    return CL_HSMqk::ClearText(params.cl_pp, params.cl_pp.dlog_in_F(c2));
}