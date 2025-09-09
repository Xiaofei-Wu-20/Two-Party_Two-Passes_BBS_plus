//
// Created by qsang on 24-10-12.
//

#ifndef PARTY_H
#define PARTY_H

#include "Utils.h"
#include "protocol_types.h"

class Party
{
public:
    Party(ProtocolParams &params, size_t id, const CL_HSMqk::PublicKey &cl_pk,
          const std::vector<CL_HSMqk::PublicKey> &cl_pk_share_vector, const CL_HSMqk::SecretKey &cl_sk_share, const CL_HSMqk::CipherText& ct_bbs_sk,
          const mcl::G2 &bbs_pk, const std::vector<mcl::G2> &bbs_pk_share_vector, const std::vector<mcl::G1>& bbs_H, const mcl::Fr &bbs_sk_share,
          const mcl::G1 &elg_pk, const std::vector<mcl::G1> &elg_pk_share_vector, const mcl::Fr &elg_sk_share);

    void setPartySet(const std::set<size_t>& party_set);

    void handleRoundOne(RoundOneData** send_data, const mcl::Fr& sid, const std::vector<mcl::Fr>& m);
    void handleRoundTwo(std::vector<RoundOneData*>& data, RoundTwoData** send_data);
    void handleOffline(std::vector<RoundTwoData*>& data, Signature** send_data);
    bool verify(const Signature& signature, const std::vector<mcl::Fr>& m) const;

private:
    void partial_decrypt(const CL_HSMqk::SecretKey &ski, const CL_HSMqk::CipherText &encrypted_message, QFI &part_dec) const;
    CL_HSMqk::ClearText agg_partial_ciphertext(
    const std::unordered_map<size_t, QFI>& pd_map,
    const CL_HSMqk::CipherText &c) const;

    std::unique_ptr<RoundOneLocalData> round1LocalData = nullptr;
    std::unique_ptr<RoundTwoLocalData> round2LocalData = nullptr;
    std::unique_ptr<Signature> signature = nullptr;

    ProtocolParams& params;
    size_t id;

    CL_HSMqk::PublicKey cl_pk;
    std::vector<CL_HSMqk::PublicKey> cl_pk_share_vector;
    CL_HSMqk::SecretKey cl_sk_share;
    CL_HSMqk::CipherText ct_bbs_sk;

    mcl::G2 bbs_pk;
    std::vector<mcl::G2> bbs_pk_share_vector;
    std::vector<mcl::G1> bbs_H;
    mcl::Fr bbs_sk_share;

    mcl::G1 elg_pk;
    std::vector<mcl::G1> elg_pk_share_vector;
    mcl::Fr elg_sk_share;

    std::set<size_t> S;
};

#endif //PARTY_H
