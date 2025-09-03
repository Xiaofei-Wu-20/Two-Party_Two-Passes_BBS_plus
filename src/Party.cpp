//
// Created by qsang on 24-10-12.
//

#include "../include/Party.h"

Party::Party(GroupParams& params, const size_t id, const CL_HSMqk::PublicKey& pk, const std::vector<CL_HSMqk::PublicKey>& pki_vector, const CL_HSMqk::SecretKey& ski, const OpenSSL::ECPoint& X, std::vector<OpenSSL::ECPoint> &X_vector, const OpenSSL::BN& xi)
            : params(params), id(id), pk(pk), pki_vector(pki_vector), Xi_vector(), X(params.ec_group, X), ski(ski), xi(xi), S()
{
    for(size_t i = 0; i < params.n; ++i)
    {
        Xi_vector.emplace_back(params.ec_group, X_vector[i]);
    }
}

void Party::setPartySet(const std::set<size_t>& party_set)
{
    S = party_set;
}

const RoundOneData& Party::getRoundOneData() const
{
    if (round1Data == nullptr) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    // RoundOneData data_copy(params.ec_group, round1Data->id, round1Data->enc_phi_share, round1Data->com_i, round1Data->zk_proof_cl_enc);
    // return data_copy;
    return *round1Data;
}

RoundTwoData Party::getRoundTwoData() const
{
    if (round2Data == nullptr) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    RoundTwoData data_copy(round2Data->id, params.ec_group, round2Data->phi_x_share, round2Data->phi_k_share, round2Data->Ri, round2Data->open_i, ECNIZKProof(params.ec_group, round2Data->zk_proof_dl), CL_HSMqk_DL_CL_ZKProof(params.ec_group, round2Data->zk_proof_dl_cl_x), CL_HSMqk_DL_CL_ZKProof(params.ec_group, round2Data->zk_proof_dl_cl_k));
    return data_copy;
}

const RoundThreeData& Party::getRoundThreeData() const
{
    if (round3Data == nullptr) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    return *round3Data;
}

const Signature& Party::getSignature() const
{
    if (!signature) {
        throw std::runtime_error("Round one data is not initialized.");
    }
    return *signature;
}

std::tuple<Commitment, CommitmentSecret> Party::commit(const OpenSSL::ECPoint &Q) const
{
    size_t nbytes = static_cast<size_t>(params.sec_level) >> 3;
    CommitmentSecret r(nbytes);
    OpenSSL::random_bytes (r.data(), nbytes);
    return std::make_tuple(params.H(r, OpenSSL::ECPointGroupCRefPair(Q, params.ec_group)), r);
}

std::tuple<Commitment, CommitmentSecret> Party::commit(const OpenSSL::ECPoint &Q1, const OpenSSL::ECPoint &Q2) const
{
    size_t nbytes = static_cast<size_t>(params.sec_level) >> 3;
    CommitmentSecret r(nbytes);
    OpenSSL::random_bytes (r.data(), nbytes);
    return std::make_tuple (params.H(r, OpenSSL::ECPointGroupCRefPair (Q1, params.ec_group), OpenSSL::ECPointGroupCRefPair (Q2, params.ec_group)), r);
}

bool Party::open(const Commitment &c, const OpenSSL::ECPoint &Q, const CommitmentSecret &r) const
{
    Commitment c2 (params.H(r, OpenSSL::ECPointGroupCRefPair (Q, params.ec_group)));
    return c == c2;
}

bool Party::open(const Commitment &c, const OpenSSL::ECPoint &Q1, const OpenSSL::ECPoint &Q2, const CommitmentSecret &r) const
{
    Commitment c2 (params.H(r, OpenSSL::ECPointGroupCRefPair (Q1, params.ec_group), OpenSSL::ECPointGroupCRefPair(Q2, params.ec_group)));
    return c == c2;
}

void Party::handleRoundOne()
{
    RandGen randgen;

    OpenSSL::BN phi_share = params.ec_group.random_mod_order();
    OpenSSL::BN k_share = params.ec_group.random_mod_order();
    OpenSSL::ECPoint R_share(params.ec_group, k_share);
    Mpz r(randgen.random_mpz(params.cl_pp.encrypt_randomness_bound()));
    CL_HSMqk::ClearText ct (params.cl_pp, static_cast<Mpz>(phi_share));
    CL_HSMqk::CipherText enc_phi_share = params.cl_pp.encrypt(pk, ct, r);

    Commitment com_i;
    CommitmentSecret open_i;
    tie(com_i, open_i) = commit(R_share);

    ECNIZKProof zk_proof_dl(params.ec_group, params.H, k_share);
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc(params.cl_pp, params.H, pk, enc_phi_share, ct, r, randgen);

    round1Data = std::make_unique<RoundOneData>(id, enc_phi_share, com_i, zk_proof_cl_enc);
    round1LocalData = std::make_unique<RoundOneLocalData>(id, params.ec_group, phi_share, k_share, R_share, enc_phi_share, com_i, open_i, zk_proof_dl);
}

void Party::handleRoundTwo(std::vector<RoundOneData>& data)
{
    RandGen randgen;

    // filter
    data.erase(
        std::remove_if(data.begin(), data.end(),
            [this](const RoundOneData& d) {
                return !d.zk_proof_cl_enc.verify(params.cl_pp, params.H, pk, d.enc_phi_share);
            }),
        data.end()
    );

    if (data.size() < params.t + 1) {
        throw std::runtime_error("Party " + std::to_string(id) + ": zk proof not up to t");
    }

    CL_HSMqk::CipherText enc_phi = data[0].enc_phi_share;
    round1LocalData->com_list.reserve(data.size());
    round1LocalData->com_list.emplace(data[0].id, data[0].com_i);

    for(size_t i = 1; i < data.size(); ++i)
    {
        enc_phi = params.cl_pp.add_ciphertexts(pk, enc_phi, data[i].enc_phi_share, Mpz("0"));
        round1LocalData->com_list.emplace(data[i].id, data[i].com_i);
    }

    OpenSSL::BN omega;
    omega = lagrange_at_zero(params.ec_group, S, id);
    params.ec_group.mul_mod_order (omega, omega, xi);
    OpenSSL::ECPoint Xi(params.ec_group, omega);

    CL_HSMqk::CipherText phi_x_share = params.cl_pp.scal_ciphertexts(pk, enc_phi, static_cast<Mpz>(omega), Mpz("0"));
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x(params.cl_pp, params.ec_group, params.H, OpenSSL::ECPoint(params.ec_group, Xi), enc_phi, phi_x_share, CL_HSMqk::ClearText(params.cl_pp, static_cast<Mpz>(omega)), randgen);
    // bool ret = zk_proof_dl_cl_x.verify(params.cl_pp, params.ec_group, params.H, Xi, enc_phi, phi_x_share);

    CL_HSMqk::CipherText phi_k_share = params.cl_pp.scal_ciphertexts(pk, enc_phi, static_cast<Mpz>(round1LocalData->k_share), Mpz("0"));
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k(params.cl_pp, params.ec_group, params.H, OpenSSL::ECPoint(params.ec_group, round1LocalData->R_share), enc_phi, phi_k_share, CL_HSMqk::ClearText(params.cl_pp, static_cast<Mpz>(round1LocalData->k_share)), randgen);

    round2Data = std::make_unique<RoundTwoData>(id, params.ec_group, phi_x_share, phi_k_share, round1LocalData->R_share, round1LocalData->open_i, round1LocalData->zk_proof_dl, zk_proof_dl_cl_x, zk_proof_dl_cl_k);
    round2LocalData = std::make_unique<RoundTwoLocalData>(id, enc_phi);
}

void Party::handleRoundThree(std::vector<RoundTwoData>& data, const std::vector<unsigned char>& m)
{
    RandGen randgen;

    // filter
    data.erase(
    std::remove_if(data.begin(), data.end(),
    [this](const RoundTwoData& d) {
        OpenSSL::ECPoint Xi(params.ec_group, Xi_vector[d.id-1]);
        params.ec_group.scal_mul(Xi,lagrange_at_zero(params.ec_group, S, d.id) , Xi);
        return !(open(round1LocalData->com_list[d.id], d.Ri, d.open_i) &
            d.zk_proof_dl.verify(params.ec_group, params.H, d.Ri) &
            d.zk_proof_dl_cl_x.verify(params.cl_pp, params.ec_group, params.H, OpenSSL::ECPoint(params.ec_group, Xi), round2LocalData->enc_phi, d.phi_x_share) &
            d.zk_proof_dl_cl_k.verify(params.cl_pp, params.ec_group, params.H, OpenSSL::ECPoint(params.ec_group, d.Ri), round2LocalData->enc_phi, d.phi_k_share)
                );
    }),
    data.end()
    );

    if (data.size() < params.t + 1) {
        throw std::runtime_error("Party " + std::to_string(id) + ": not up to threshold");
    }

    OpenSSL::ECPoint R(params.ec_group, data[0].Ri);
    CL_HSMqk::CipherText c0 = data[0].phi_k_share;
    CL_HSMqk::CipherText c1_r = data[0].phi_x_share;

    OpenSSL::BN rx;
    OpenSSL::BN h (params.H(m));

    for (size_t i = 1; i < data.size(); ++i)
    {
        params.ec_group.ec_add(R, R, data[i].Ri);
        c0 = params.cl_pp.add_ciphertexts(pk, c0, data[i].phi_k_share, Mpz("0"));
        c1_r = params.cl_pp.add_ciphertexts(pk, c1_r, data[i].phi_x_share, Mpz("0"));
    }

    params.ec_group.x_coord_of_point(rx, R);
    params.ec_group.mod_order(rx, rx);
    c1_r = params.cl_pp.scal_ciphertexts(pk, c1_r, static_cast<Mpz>(rx), Mpz("0"));
    CL_HSMqk::CipherText c1_l = params.cl_pp.scal_ciphertexts(pk, round2LocalData->enc_phi, static_cast<Mpz>(h), Mpz("0"));
    CL_HSMqk::CipherText c1 = params.cl_pp.add_ciphertexts(pk, c1_l, c1_r, Mpz("0"));

    QFI part_c0_dec_share, part_c1_dec_share;

    partial_decrypt(ski, c0, part_c0_dec_share);
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0(params.cl_pp, params.H, pki_vector[id-1], c0, part_c0_dec_share, ski, randgen);
    // bool ret = zk_proof_pd_c0.verify(params.cl_pp, params.H, pki_vector[id-1], c0, part_c0_dec_share);
    partial_decrypt(ski, c1, part_c1_dec_share);
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1(params.cl_pp, params.H, pki_vector[id-1], c1, part_c1_dec_share, ski, randgen);

    round3Data = std::make_unique<RoundThreeData>(id, part_c0_dec_share, part_c1_dec_share, zk_proof_pd_c0, zk_proof_pd_c1);
    round3LocalData = std::make_unique<RoundThreeLocalData>(id, c0, c1, rx);
}

    void Party::handleOffline(std::vector<RoundThreeData>& data)
{
    /*std::vector<QFI> part_c0_dec_shares(params.n);
    part_c0_dec_shares.push_back(round3Data->c0_dec_share);
    std::vector<QFI> part_c1_dec_shares(params.n);
    part_c1_dec_shares.push_back(round3Data->c1_dec_share);

    for(unsigned int i = 1; i < params.n+1; ++i)
    {
        unsigned int index = i - 1;
        if (i != id)
        {
            part_c0_dec_shares.push_back(data[index].c0_dec_share);
            part_c1_dec_shares.push_back(data[index].c1_dec_share);
        }
    }*/

    data.erase(
    std::remove_if(data.begin(), data.end(),
    [this](const RoundThreeData& data) {
        return !(data.zk_proof_pd_c0.verify(params.cl_pp, params.H, pki_vector[data.id-1], round3LocalData->c0, data.c0_dec_share) &
            data.zk_proof_pd_c1.verify(params.cl_pp, params.H, pki_vector[data.id-1], round3LocalData->c1, data.c1_dec_share)
            );
    }),
     data.end()
    );

    if (data.size() < params.t + 1) {
        throw std::runtime_error("Party " + std::to_string(id) + ": not up to threshold");
    }

    std::unordered_map<size_t, QFI> part_c0_dec_shares;
    std::unordered_map<size_t, QFI> part_c1_dec_shares;
    part_c0_dec_shares.reserve(data.size());
    part_c1_dec_shares.reserve(data.size());

    for(size_t i = 0; i < data.size(); ++i)
    {
        part_c0_dec_shares[data[i].id] = data[i].c0_dec_share;
        part_c1_dec_shares[data[i].id] = data[i].c1_dec_share;
    }

    CL_HSMqk::ClearText m0 = agg_partial_ciphertext(part_c0_dec_shares, round3LocalData->c0);
    CL_HSMqk::ClearText m1 = agg_partial_ciphertext(part_c1_dec_shares, round3LocalData->c1);

    OpenSSL::BN inv_m0, s;
    OpenSSL::BN m00_bn (m0);
    OpenSSL::BN m11_bn (m1);

    params.ec_group.inverse_mod_order(inv_m0, m00_bn);
    params.ec_group.mul_mod_order(s, inv_m0, m11_bn);

    signature = std::make_unique<Signature>(round3LocalData->rx, s);
}

bool Party::verify(const Signature& signature, const std::vector<unsigned char>& m) const
{
    OpenSSL::BN h (params.H(m));
    OpenSSL::BN inv_s, u1, u2, rx;
    OpenSSL::ECPoint R (params.ec_group);

    params.ec_group.inverse_mod_order(inv_s, signature.s);
    params.ec_group.mul_mod_order (u1, inv_s, h);
    params.ec_group.mul_mod_order (u2, inv_s, signature.rx);
    params.ec_group.scal_mul(R, u1, u2, X);

    params.ec_group.x_coord_of_point (rx, R);
    params.ec_group.mod_order (rx, rx);
    return (rx == signature.rx);
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
        params.cl_pp.Cl_G().nupow (num, pd_map.at(s), cl_lagrange_at_zero(S, s, params.delta));
        params.cl_pp.Cl_Delta().nucompinv(c2, c2, num);
    }
    return CL_HSMqk::ClearText(params.cl_pp, params.cl_pp.dlog_in_F(c2));
}