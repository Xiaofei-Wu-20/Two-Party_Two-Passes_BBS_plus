//
// Created by qsang on 24-10-12.
//

#include "../include/Party.h"
#include "../include/threshold_elgamal.h"
#include "../include/protocol_types.h"

Party::Party(ProtocolParams &params, size_t id, const CL_HSMqk::PublicKey &cl_pk,
             const std::vector<CL_HSMqk::PublicKey> &cl_pk_share_vector, const CL_HSMqk::SecretKey &cl_sk_share,
             const CL_HSMqk::CipherText &ct_bbs_sk, const mcl::G2& bbs_pk,
             const std::vector<mcl::G2> &bbs_pk_share_vector, const std::vector<mcl::G1>& bbs_H,
             const mcl::Fr& bbs_sk_share, const mcl::G1& elg_pk, const std::vector<mcl::G1>& elg_pk_share_vector,
             const mcl::Fr& elg_sk_share)
: params(params), id(id), cl_pk(cl_pk), cl_pk_share_vector(cl_pk_share_vector), cl_sk_share(cl_sk_share), ct_bbs_sk(ct_bbs_sk),
bbs_pk(bbs_pk), bbs_pk_share_vector(bbs_pk_share_vector), bbs_H(bbs_H), bbs_sk_share(bbs_sk_share),
elg_pk(elg_pk), elg_pk_share_vector(elg_pk_share_vector), elg_sk_share(elg_sk_share), S()
{ }

void Party::setPartySet(const std::set<size_t>& party_set)
{
    S = party_set;
}

void Party::handleRoundOne(RoundOneData** send_data, const mcl::Fr& sid, const std::vector<mcl::Fr>& m)
{
    mcl::G1 y;
    std::vector<mcl::Fr> hash_input;
    hash_input.reserve(m.size() + 1);
    hash_input.insert(hash_input.end(), m.begin(), m.end());
    hash_input.push_back(sid);
    mcl::hashAndMapToG1(y, hash_input.data(), hash_input.size());

    mcl::G1 m_share;
    mcl::G1::mul(m_share, y, elg_sk_share);

    mcl::Fr gamma_share; gamma_share.setByCSPRNG();
    Mpz gamma_share_mpz; utils::fr_to_mpz(gamma_share_mpz, gamma_share);
    RandGen randgen;
    Mpz beta_1(randgen.random_mpz(params.cl_pp.encrypt_randomness_bound()));
    Mpz beta_2(randgen.random_mpz(params.cl_pp.encrypt_randomness_bound()));

    CL_HSMqk::ClearText ct(params.cl_pp, gamma_share_mpz);
    CL_HSMqk::CipherText c_gamma_share = params.cl_pp.encrypt(cl_pk, ct, beta_1);
    CL_HSMqk::CipherText c_gamma_x_share = params.cl_pp.scal_ciphertexts(cl_pk, ct_bbs_sk, gamma_share_mpz, beta_2);

    mcl::G1 D = params.g1;
    for (size_t i = 0; i < m.size(); i++) {
        mcl::G1 tmp;
        mcl::G1::mul(tmp, bbs_H[i+1], m[i]);
        mcl::G1::add(D, D, tmp);
    }

    mcl::G1 D0_share; mcl::G1::mul(D0_share, bbs_H[0], gamma_share);
    mcl::G1 D1_share; mcl::G1::mul(D1_share, D, gamma_share);

    ThresholdElgamal<mcl::G1> elgamal(params.g1, elg_pk, elg_sk_share);
    ThresholdElgamal<mcl::G1>::CipherText c_d0_share, c_d1_share;

    mcl::Fr alpha_1, alpha_2; alpha_1.setByCSPRNG(); alpha_2.setByCSPRNG();

    elgamal.encrypt(c_d0_share, D0_share, alpha_1);
    elgamal.encrypt(c_d1_share, D1_share, alpha_2);

    Elgamal_DDH_ZKProof<mcl::G1> ddh_zkp(elgamal, y, elg_pk_share_vector[id-1], m_share);
    Elgamal_CL_Consistency_ZKProof<mcl::G1> con_zkp(params.cl_pp, params.H, cl_pk, ct_bbs_sk, randgen, elgamal, bbs_H[0], D, gamma_share,
       alpha_1, alpha_2, beta_1, beta_2, c_gamma_share, c_gamma_x_share, c_d0_share, c_d1_share);

    *send_data = new RoundOneData(
        id, m_share, c_gamma_share, c_gamma_x_share, c_d0_share, c_d1_share, ddh_zkp, con_zkp
    );
    round1LocalData = std::make_unique<RoundOneLocalData>(id, y, D);
}

void Party::handleRoundTwo(std::vector<RoundOneData*>& data, RoundTwoData** send_data)
{
    RandGen randgen;
    ThresholdElgamal<mcl::G1> elgamal(params.g1, elg_pk, elg_sk_share);

    std::unordered_map<size_t, RoundOneData*> valid_data;
    for (RoundOneData* d : data) {
        if (d == nullptr) continue;

        bool ok_ddh = d->ddh_zkp.verify(elgamal, round1LocalData->y, elg_pk_share_vector[d->id - 1], d->m_share);
        bool ok_con = d->con_zkp.verify(params.cl_pp, params.H, cl_pk, elgamal, bbs_H[0], round1LocalData->D, ct_bbs_sk, d->c_gamma_share, d->c_gamma_x_share, d->c_d0_share, d->c_d1_share);

        if (ok_ddh && ok_con) {
            valid_data.emplace(d->id, d);
        }
    }

    std::set<size_t> valid_indices;
    for (auto& entry : valid_data) {
        size_t pid = entry.first;
        valid_indices.insert(pid);
    }

    if (valid_indices.size() < params.t + 1) {
        throw std::runtime_error("Party " + std::to_string(id) + ": zk proof not up to t in Round 2");
    }

    this->setPartySet(valid_indices);

    std::unordered_map<size_t, mcl::Fr> lagrange_coeffs;
    lagrange_coeffs.reserve(valid_indices.size());
    for (size_t pid : valid_indices) {
        lagrange_coeffs.emplace(pid, utils::lagrange_at_zero(S, pid));
    }

    mcl::G1 m_agg; m_agg.clear();

    for (size_t pid : valid_indices) {
        RoundOneData* d = valid_data[pid];
        mcl::G1 tmp;
        mcl::G1::mul(tmp, d->m_share, lagrange_coeffs[pid]);
        mcl::G1::add(m_agg, m_agg, tmp);
    }

    mcl::Fr e = utils::hash_g1_with_str(m_agg, "0");
    mcl::Fr s = utils::hash_g1_with_str(m_agg, "1");

    auto iter = valid_indices.begin();
    RoundOneData* d = valid_data[*iter];
    ++iter;

    CL_HSMqk::CipherText c_gamma   = d->c_gamma_share;
    CL_HSMqk::CipherText c_gamma_x = d->c_gamma_x_share;
    ThresholdElgamal<mcl::G1>::CipherText c_d0 = d->c_d0_share;
    ThresholdElgamal<mcl::G1>::CipherText c_d1 = d->c_d1_share;

    for (; iter != valid_indices.end(); ++iter) {
        RoundOneData* item = valid_data[*iter];
        c_gamma   = params.cl_pp.add_ciphertexts(cl_pk, c_gamma,   item->c_gamma_share,   Mpz("0"));
        c_gamma_x = params.cl_pp.add_ciphertexts(cl_pk, c_gamma_x, item->c_gamma_x_share, Mpz("0"));
        ThresholdElgamal<mcl::G1>::add(c_d0, c_d0, item->c_d0_share);
        ThresholdElgamal<mcl::G1>::add(c_d1, c_d1, item->c_d1_share);
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

    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0(
        params.cl_pp, params.H,
        cl_pk_share_vector[id-1],
        cl_c, part_c0_dec_share,
        cl_sk_share, randgen
    );
    Elgamal_Part_Dec_ZKProof<mcl::G1> zk_proof_pd_c1(
        elgamal, c_sd0_d1, part_c1_dec_share
    );

    *send_data = new RoundTwoData(
        id, part_c0_dec_share, part_c1_dec_share, zk_proof_pd_c0, zk_proof_pd_c1
    );
    round2LocalData = std::make_unique<RoundTwoLocalData>(id, cl_c, c_sd0_d1, e, s);
}

void Party::handleOffline(std::vector<RoundTwoData*>& data, Signature** send_data)
{

    ThresholdElgamal<mcl::G1> elgamal(params.g1, elg_pk, elg_sk_share);
    std::unordered_map<size_t, RoundTwoData*> valid_data;
    for (RoundTwoData* d : data) {
        if (d == nullptr) continue;
        bool ok_pd_c1 = d->zk_proof_pd_c1.verify(elgamal, elg_pk_share_vector[d->id - 1], round2LocalData->c_sd0_d1, d->part_c1_dec_share);
        bool ok_pd_c0 = d->zk_proof_pd_c0.verify(params.cl_pp, params.H, cl_pk_share_vector[d->id-1], round2LocalData->cl_c, d->part_c0_dec_share);

        if (ok_pd_c0 && ok_pd_c1) {
            valid_data.emplace(d->id, d);
        }
    }

    std::set<size_t> valid_indices;
    for (auto& entry : valid_data) {
        size_t pid = entry.first;
        valid_indices.insert(pid);
    }

    if (valid_indices.size() < params.t + 1) {
        throw std::runtime_error("Party " + std::to_string(id) + ": not up to t in local computation");
    }

    this->setPartySet(valid_indices);

    std::unordered_map<size_t, QFI> part_c0_dec_shares;
    std::unordered_map<size_t, mcl::G1> part_c1_dec_shares;

    for (const auto& [id, d] : valid_data) {
        part_c0_dec_shares.emplace(id, d->part_c0_dec_share);
        part_c1_dec_shares.emplace(id, d->part_c1_dec_share);
    }

    CL_HSMqk::ClearText m0 = agg_partial_ciphertext(part_c0_dec_shares, round2LocalData->cl_c);
    mcl::G1 m1;
    ThresholdElgamal<mcl::G1>::combine(m1, round2LocalData->c_sd0_d1, part_c1_dec_shares);

    mcl::Fr m0_fr, inv_m0_fr;
    utils::mpz_to_fr(m0_fr, m0);
    mcl::Fr::inv(inv_m0_fr, m0_fr);
    mcl::G1 A;
    mcl::G1::mul(A, m1, inv_m0_fr);

    *send_data = new Signature(A, round2LocalData->e, round2LocalData->s);
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


void Party::partial_decrypt(const CL_HSMqk::SecretKey &ski, const CL_HSMqk::CipherText &encrypted_message, QFI &part_dec) const
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