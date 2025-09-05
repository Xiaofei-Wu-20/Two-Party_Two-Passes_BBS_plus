#pragma once

#include "Utils.h"
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