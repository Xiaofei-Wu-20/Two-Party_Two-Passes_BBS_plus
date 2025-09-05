//
// Created by qsang on 24-10-12.
//

#ifndef UTILS_H
#define UTILS_H

#include <set>
#include <vector>
#include "bicycl/bicycl.hpp"
#include <mcl/bls12_381.hpp>

using namespace BICYCL;

namespace utils {

    inline void fr_to_mpz(Mpz& mpz, const mcl::Fr& fr) {
        std::string str = fr.getStr();
        mpz_set_str(mpz.mpz_, str.c_str(), 10);
    }

    inline void mpz_to_fr(mcl::Fr& fr, const Mpz& mpz) {
        char* str = mpz_get_str(NULL, 10, mpz.mpz_);
        bool success;
        fr.setStr(&success, str);
        free(str);
        if (!success) {
            throw std::runtime_error("Failed to convert mpz to Fr");
        }
    }
    // Randomly generates a message of at least 4 bytes.
    inline void randomize_messages(std::vector<mcl::Fr>& m, size_t ell) {
        for (size_t i = 0; i < ell; i++) {
            m[i].setByCSPRNG();
        }
    }

    inline std::set<size_t> select_parties(RandGen& rng, const size_t n, const size_t t)
    {
        if (t >= n) {
            throw std::invalid_argument("t cannot be greater than n-1");
        }

        std::set<size_t> parties;
        while (parties.size() < t + 1) {
            parties.insert(rng.random_ui(n) + 1);
        }
        return parties;
    }

    // Computes the factorial of a number.
    inline Mpz factorial(size_t n)
    {
        Mpz res = Mpz("1");
        for (size_t j = 2; j < n + 1; ++j)
        {
            Mpz::mul(res, res, j);
        }
        return res;
    }

    // Lagrange interpolation in the context of class groups.
    inline Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta)
    {
        Mpz numerator("1"), denominator("1"), result;
        for (size_t j : S) {
            if (j != i) {
                Mpz::mul(numerator, numerator, j);
                if (j > i) {
                    Mpz::mul(denominator, denominator, j - i);
                } else {
                    Mpz::mul(denominator, denominator, i - j);
                    denominator.neg();
                }
            }
        }

        Mpz::divexact(result, delta, denominator);
        Mpz::mul(result, result, numerator);
        return result;
    }

    // Lagrange interpolation in the context of elliptic curves.
    inline mcl::Fr lagrange_at_zero(const std::set<size_t>& S, const size_t i)
    {
        mcl::Fr numerator, denominator, result;

        numerator = 1UL;
        denominator = 1UL;
        for (size_t j : S) {
            if (j != i) {
                mcl::Fr::mul(numerator, numerator, j);
                if (j > i) {
                    mcl::Fr::mul(denominator, denominator, j - i);
                } else {
                    mcl::Fr::mul(denominator, denominator, i - j);
                    mcl::Fr::neg(denominator, denominator);
                }
            }
        }
        mcl::Fr::inv(result, denominator);
        mcl::Fr::mul(result, result, numerator);

        return result;
    }

    inline mcl::Fr hash_g1_to_fr(const mcl::G1& point) {
        mcl::Fr result;
        size_t size = point.serialize(nullptr, 0);
        std::vector<uint8_t> buf(size);
        point.serialize(buf.data(), size);
        result.setHashOf(buf.data(), size);
        return result;
    }
}

#endif //UTILS_H
