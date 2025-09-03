//
// Created by qsang on 24-10-12.
//

#include <vector>
#include <set>
#include "../include/Utils.h"

// Randomly generates a message of at least 4 bytes.
void randomize_message(std::vector<unsigned char>& m) {
    unsigned char size;
    OpenSSL::random_bytes(&size, sizeof(unsigned char));
    size = (size < 4) ? 4 : size;

    m.resize(size);
    OpenSSL::random_bytes(m.data(), m.size() * sizeof(unsigned char));
}

std::set<size_t> select_parties(RandGen& rng, const size_t n, const size_t t)
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
Mpz factorial(size_t n)
{
    Mpz res = Mpz("1");
    for (size_t j = 2; j < n + 1; ++j)
    {
        Mpz::mul(res, res, j);
    }
    return res;
}

// Lagrange interpolation in the context of class groups.
Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta)
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
OpenSSL::BN lagrange_at_zero(const OpenSSL::ECGroup &E, const std::set<size_t>& S, const size_t i)
{
    OpenSSL::BN numerator, denominator, result;

    numerator = 1UL;
    denominator = 1UL;
    for (size_t j : S) {
        if (j != i) {
            E.mul_by_word_mod_order(numerator, j);
            if (j > i) {
                E.mul_by_word_mod_order(denominator, j - i);
            } else {
                E.mul_by_word_mod_order(denominator, i - j);
                denominator.neg();
            }
        }
    }
    E.inverse_mod_order(result, denominator);
    E.mul_mod_order(result, result, numerator);

    return result;
}
