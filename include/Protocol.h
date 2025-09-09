//
// Created by qsang on 24-10-12.
//

#ifndef PROTOCOL_H
#define PROTOCOL_H

#include "Party.h"
#include "Utils.h"

class Protocol
{
public:
    explicit Protocol(ProtocolParams& params);
    void dkg();
    void run(const std::set<size_t>& party_set, const std::vector<mcl::Fr>& message, std::vector<Signature*>& results);
    bool verify(const std::vector<Signature*>& bss_sig, const std::vector<mcl::Fr>& message) const;
    ProtocolParams& params;
    mcl::G2 sig_public_key_g2;
    std::vector<mcl::G1> sig_public_key_g1;
    std::vector<Party> S;
};

#endif //PROTOCOL_H
