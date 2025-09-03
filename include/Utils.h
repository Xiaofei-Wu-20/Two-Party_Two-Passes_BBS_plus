//
// Created by qsang on 24-10-12.
//

#ifndef UTILS_H
#define UTILS_H

#include <set>
#include <unordered_map>
#include <vector>
#include "bicycl/bicycl.hpp"

using namespace BICYCL;
using Commitment = OpenSSL::HashAlgo::Digest;
using CommitmentSecret = std::vector<unsigned char>;

void randomize_message(std::vector<unsigned char>& m);
Mpz factorial(size_t n);
Mpz cl_lagrange_at_zero(const std::set<size_t>& S, size_t i, const Mpz& delta);
OpenSSL::BN lagrange_at_zero(const OpenSSL::ECGroup &E, const std::set<size_t>& S, size_t i);
std::set<size_t> select_parties(RandGen& rng, size_t n, size_t t);

struct NDSS24
{
    int id_r1, id_r2, id_r3, id_r4;

    OpenSSL::ECGroup e0;
    CL_HSMqk c0;
    OpenSSL::HashAlgo h0;

    CL_HSMqk::CipherText cipher_ki;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    CL_HSMqk::CipherText cipher_xi_k;
    CL_HSMqk::CipherText cipher_gammai_k;
    OpenSSL::ECPoint cipher_g_gammai_0;
    OpenSSL::ECPoint cipher_g_gammai_1;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl;
    CL_HSMqk_DL_CL_ZKProof zk_proof_el_cl;
    Mpz z_2;

    QFI pd0, pd1;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0, zk_proof_pd_c1;

    QFI pd2;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c2;

    NDSS24(RandGen& rng, SecLevel seclevel) : id_r1(1), id_r2(2), id_r3(3), id_r4(4),
    e0(seclevel), c0(e0.order(), 1, seclevel, rng), h0(seclevel),

    cipher_ki(c0, c0.keygen(CL_HSMqk::SecretKey(c0, rng.random_mpz(c0.secretkey_bound()))), CL_HSMqk::ClearText(c0, rng), Mpz("1")),
    zk_proof_cl_enc(c0, h0, c0.keygen(CL_HSMqk::SecretKey(c0, rng.random_mpz(c0.secretkey_bound()))), cipher_ki, CL_HSMqk::ClearText(c0, rng), Mpz("1"), rng),

    cipher_xi_k(cipher_ki),
    cipher_gammai_k(cipher_ki),
    cipher_g_gammai_0(e0),
    cipher_g_gammai_1(e0),
    zk_proof_dl_cl(c0, e0, h0, OpenSSL::ECPoint(e0), cipher_xi_k, cipher_xi_k, CL_HSMqk::ClearText(c0, rng), rng),
    zk_proof_el_cl(e0, zk_proof_dl_cl),
    z_2(rng.random_bytes(32)),

    pd0(cipher_ki.c1()), pd1(cipher_ki.c1()), pd2(cipher_ki.c1()),
    zk_proof_pd_c0(c0, h0, c0.keygen(CL_HSMqk::SecretKey(c0, rng.random_mpz(c0.secretkey_bound()))), cipher_xi_k, pd0, CL_HSMqk::SecretKey(c0, rng.random_mpz(c0.secretkey_bound())), rng),
    zk_proof_pd_c1(zk_proof_pd_c0),
    zk_proof_pd_c2(zk_proof_pd_c0)
    {};

    size_t getSize()
    {
        size_t b0 = 0;

        b0 += sizeof(id_r1);
        b0 += sizeof(id_r2);
        b0 += sizeof(id_r3);
        b0 += sizeof(id_r4);
        std::cout << "init:" << b0 / 1024.0<< std::endl;

        auto N = 1827 / (8 * 1024.0), G = 256 / (8 * 1024.0);
        size_t b1 = 0;
        b1 += cipher_ki.get_bytes();
        b1 += zk_proof_cl_enc.get_bytes();
        std::cout << "r1:" << b1 / 1024.0 << std::endl;
        std::cout << "s1:" << 5 * N + G << std::endl;

        size_t b2 = 0;
        b2 += cipher_xi_k.get_bytes();
        b2 += cipher_gammai_k.get_bytes();
        b2 += cipher_g_gammai_0.get_bytes();
        b2 += cipher_g_gammai_1.get_bytes();
        b2 += zk_proof_dl_cl.get_bytes_dl();
        b2 += zk_proof_el_cl.get_bytes_el();
        std::cout << "r2:" << b2 / 1024.0 << std::endl;
        std::cout << "s2:" << 10 * N + 6 * G << std::endl;

        size_t b3 = 0;
        b3 += pd0.get_bytes();
        // b3 += pd1.get_bytes();
        b3 += 32;
        b3 += zk_proof_pd_c0.get_bytes();
        // b3 += zk_proof_pd_c0.get_bytes();
        b3 += 3 * 32;
        std::cout << "r3:" << b3 / 1024.0 << std::endl;
        std::cout << "s3:" << 4 * N + 4 * G << std::endl;

        size_t b4 = 0;
        b4 += pd2.get_bytes();
        //std::cout << "r4-1:" << b4 << std::endl;
        b4 += zk_proof_pd_c2.get_bytes();
        //std::cout << "r4-2:" << zk_proof_pd_c2.get_bytes() << std::endl;
        std::cout << "r4:" << b4 / 1024.0 << std::endl;

        double ideal = 19 * N + 11 * G;
        std::cout << "ideal total:" << ideal << std::endl;
        ideal = 3.4;
        std::cout << "ideal total:" << ideal * 5 << " | " << ideal * 10 << " | " << ideal * 15 << " | " << ideal * 20 << std::endl;
        return (b1 + b2 + b3);
    }
};

struct TECDSA
{
    size_t id1;
    // CL_HSMqk C;
    // OpenSSL::HashAlgo H;

    Commitment com_i;
    CL_HSMqk::PublicKey pk;
    CL_HSMqk::CipherText enc_phi_share;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    size_t id2;
    OpenSSL::ECPoint Ri;
    CommitmentSecret open_i;
    ECNIZKProof zk_proof_dl;

    // CL_HSMqk C2;
    // OpenSSL::HashAlgo H2;
    OpenSSL::ECGroup E2;
    OpenSSL::ECPoint X21, X22;
    CL_HSMqk::CipherText phi21, phi22;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;

    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    size_t id3;
    // CL_HSMqk C3;
    // OpenSSL::HashAlgo H3;
    CL_HSMqk::PublicKey pk31, pk32;
    CL_HSMqk::CipherText cc31, cc32;
    QFI c0_dec_share;
    QFI c1_dec_share;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1;
};

// Data structures for different rounds of the protocol.
struct RoundOneData {
    size_t id;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CL_HSMqk_ZKAoKProof zk_proof_cl_enc;

    RoundOneData(const size_t id, const CL_HSMqk::CipherText& share, const Commitment& com_i, const CL_HSMqk_ZKAoKProof& proof) : id(id), enc_phi_share(share), com_i(com_i), zk_proof_cl_enc(proof) {}
    size_t getSize()
    {
        return sizeof(RoundOneData);
    }
};

struct RoundOneLocalData {
    size_t id;
    OpenSSL::BN phi_share;
    OpenSSL::BN k_share;
    OpenSSL::ECPoint R_share;
    CL_HSMqk::CipherText enc_phi_share;
    Commitment com_i;
    CommitmentSecret open_i;
    std::unordered_map<size_t, Commitment> com_list;
    ECNIZKProof zk_proof_dl;

    size_t data_two_size = 0;

    RoundOneLocalData(const size_t id, const OpenSSL::ECGroup& E, const OpenSSL::BN& phi, const OpenSSL::BN& k, const OpenSSL::ECPoint& R, const CL_HSMqk::CipherText& ct, const Commitment& com_i, const CommitmentSecret& open_i, const ECNIZKProof& zk_proof)
        : id(id), phi_share(phi), k_share(k), R_share(E, R), enc_phi_share(ct), com_i(com_i), open_i(open_i), zk_proof_dl(E, zk_proof)
    {
        com_list.emplace(this->id, com_i);

        data_two_size += sizeof(id);
        data_two_size += phi_share.num_bytes();
        data_two_size += k_share.num_bytes();
        data_two_size += sizeof(enc_phi_share);
        data_two_size += com_i.size() * sizeof(char);
        data_two_size += open_i.size() * sizeof(unsigned char);

    }
};

struct RoundTwoData {
    size_t id;
    CL_HSMqk::CipherText phi_x_share;
    CL_HSMqk::CipherText phi_k_share;
    OpenSSL::ECPoint Ri;
    CommitmentSecret open_i;
    ECNIZKProof zk_proof_dl;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_x;
    CL_HSMqk_DL_CL_ZKProof zk_proof_dl_cl_k;

    RoundTwoData(const size_t id, const OpenSSL::ECGroup& E, const CL_HSMqk::CipherText& phi_x, const CL_HSMqk::CipherText& phi_k, const OpenSSL::ECPoint& R, const CommitmentSecret& open_i, const ECNIZKProof& zk_proof_dl, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_x, const CL_HSMqk_DL_CL_ZKProof& zk_proof_dl_cl_k)
        : id(id), phi_x_share(phi_x), phi_k_share(phi_k), Ri(E, R), open_i(open_i), zk_proof_dl(E, zk_proof_dl), zk_proof_dl_cl_x(E, zk_proof_dl_cl_x), zk_proof_dl_cl_k(E, zk_proof_dl_cl_k) {}
};

struct RoundTwoLocalData {
    size_t id;
    CL_HSMqk::CipherText enc_phi;

    RoundTwoLocalData(const size_t id, const CL_HSMqk::CipherText& phi)
        : id(id), enc_phi(phi) {}
};

struct RoundThreeData {
    size_t id;
    QFI c0_dec_share;
    QFI c1_dec_share;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c0;
    CL_HSMqk_Part_Dec_ZKProof zk_proof_pd_c1;

    RoundThreeData(const size_t id, const QFI& c0_dec_share, const QFI& c1_dec_share, const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c0, const CL_HSMqk_Part_Dec_ZKProof& zk_proof_pd_c1)
        : id(id), c0_dec_share(c0_dec_share), c1_dec_share(c1_dec_share), zk_proof_pd_c0(zk_proof_pd_c0), zk_proof_pd_c1(zk_proof_pd_c1) {}
};

struct RoundThreeLocalData {
    size_t id;
    CL_HSMqk::CipherText c0;
    CL_HSMqk::CipherText c1;
    OpenSSL::BN rx;

    RoundThreeLocalData(const size_t id, const CL_HSMqk::CipherText& c0, const CL_HSMqk::CipherText& c1, const OpenSSL::BN& rx)
        : id(id), c0(c0), c1(c1), rx(rx) {}
};

struct Signature {
    OpenSSL::BN rx;
    OpenSSL::BN s;

    Signature(const OpenSSL::BN& rx, const OpenSSL::BN& s) : rx(rx), s(s) {}
};

// Class holding group parameters for the protocol.
class GroupParams {
public:
    SecLevel sec_level;
    size_t n;
    size_t t;
    Mpz delta;
    OpenSSL::ECGroup ec_group;
    OpenSSL::HashAlgo H;
    CL_HSMqk cl_pp;

    GroupParams(SecLevel seclevel, size_t n, size_t t, RandGen& randgen)
    : sec_level(seclevel), n(n), t(t), delta(factorial(n)), ec_group(seclevel), H(seclevel), cl_pp(ec_group.order(), 1, seclevel, randgen) {}
};

#endif //UTILS_H
