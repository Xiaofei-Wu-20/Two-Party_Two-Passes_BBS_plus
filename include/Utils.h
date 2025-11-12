//
// Created by qsang on 24-10-12.
//

#ifndef UTILS_H
#define UTILS_H

#include <set>
#include <vector>
#include "bicycl/bicycl.hpp"
#include <mcl/bls12_381.hpp>
#include <openssl/sha.h>
#include <cstring>  // for memcpy

using namespace BICYCL;

using G1 = mcl::bn::G1;
using G2 = mcl::bn::G2;
using Fr = mcl::bn::Fr;


namespace utils {

    // inline void fr_to_mpz(Mpz& mpz, const Fr& fr) {
    //     std::string str = fr.getStr();
    //     mpz_set_str(mpz.mpz_, str.c_str(), 10);
    // }
    // inline void mpz_to_fr(Fr& fr, const Mpz& mpz) {
    //     char* str = mpz_get_str(NULL, 10, mpz.mpz_);
    //     bool success;
    //     fr.setStr(&success, str);
    //     free(str);
    //     if (!success) {
    //         throw std::runtime_error("Failed to convert mpz to Fr");
    //     }
    // }
    // Randomly generates a message of at least 4 bytes.
    inline void fr_to_mpz(Mpz& mpz, const Fr& fr) {
        static Mpz mod_bound("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        std::string str = fr.getStr(10);
        mpz_set_str(mpz.mpz_, str.c_str(), 10);
        if (mpz_cmp_si(mpz.mpz_, 0) < 0)
            mpz_add(mpz.mpz_, mpz.mpz_, mod_bound.mpz_);
        mpz_mod(mpz.mpz_, mpz.mpz_, mod_bound.mpz_);
    }
    inline void mpz_to_fr(Fr& fr, const Mpz& mpz) {
        static Mpz mod_bound("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001");
        Mpz reduced;
        mpz_mod(reduced.mpz_, mpz.mpz_, mod_bound.mpz_);
        char* str = mpz_get_str(NULL, 10, reduced.mpz_);
        bool success;
        fr.setStr(&success, str);
        free(str);
        if (!success) {
            throw std::runtime_error("Failed to convert mpz to Fr (after mod)");
        }
    }
    // inline void randomize_messages(std::vector<Fr>& m, size_t ell) {
    //     for (size_t i = 0; i < ell; i++) {
    //         m[i].setByCSPRNG();
    //     }
    // }

    // inline std::set<size_t> select_parties(RandGen& rng, const size_t n, const size_t t)
    // {
    //     if (t >= n) {
    //         throw std::invalid_argument("t cannot be greater than n-1");
    //     }

    //     std::set<size_t> parties;
    //     while (parties.size() < t + 1) {
    //         parties.insert(rng.random_ui(n) + 1);
    //     }
    //     return parties;
    // }

    // // Computes the factorial of a number.
    // inline Mpz factorial(size_t n)
    // {
    //     Mpz res = Mpz("1");
    //     for (size_t j = 2; j < n + 1; ++j)
    //     {
    //         Mpz::mul(res, res, j);
    //     }
    //     return res;
    // }

    // // Lagrange interpolation in the context of class groups.
    // inline Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta)
    // {
    //     Mpz numerator("1"), denominator("1"), result;
    //     for (size_t j : S) {
    //         if (j != i) {
    //             Mpz::mul(numerator, numerator, j);
    //             if (j > i) {
    //                 Mpz::mul(denominator, denominator, j - i);
    //             } else {
    //                 Mpz::mul(denominator, denominator, i - j);
    //                 denominator.neg();
    //             }
    //         }
    //     }

    //     Mpz::divexact(result, delta, denominator);
    //     Mpz::mul(result, result, numerator);
    //     return result;
    // }

    // // Lagrange interpolation in the context of elliptic curves.
    // inline Fr lagrange_at_zero(const std::set<size_t>& S, const size_t i)
    // {
    //     Fr numerator, denominator, result;

    //     numerator = 1UL;
    //     denominator = 1UL;
    //     for (size_t j : S) {
    //         if (j != i) {
    //             Fr::mul(numerator, numerator, j);
    //             if (j > i) {
    //                 Fr::mul(denominator, denominator, j - i);
    //             } else {
    //                 Fr::mul(denominator, denominator, i - j);
    //                 Fr::neg(denominator, denominator);
    //             }
    //         }
    //     }
    //     Fr::inv(result, denominator);
    //     Fr::mul(result, result, numerator);

    //     return result;
    // }

    // inline Fr hash_g1_with_str(const mcl::bn::G1& point, const std::string& str) {
    //     Fr result;
    //     size_t point_size = point.serialize(nullptr, 0);
    //     std::vector<uint8_t> buf(point_size + str.length());
    //     point.serialize(buf.data(), point_size);
    //     memcpy(buf.data() + point_size, str.data(), str.length());
    //     result.setHashOf(buf.data(), buf.size());
    //     return result;
    // }
}

#endif //UTILS_H
