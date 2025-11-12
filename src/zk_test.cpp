#include "../include/zk_sigma.h"
#include <iostream>
#include "../include/bicycl/bicycl.hpp"

extern "C" {
    #include "../include/ecvrf_test.h"
}

using namespace mcl::bn;
using namespace BICYCL;
using namespace ZK;

int main() {

    GlobalContext::init();

    // === 椭圆曲线侧参数 ===
    G2 G2_;
    mcl::bn::hashAndMapToG2(G2_, "1");
    Fr x1; x1.setByCSPRNG();
    G2 X_1; G2::mul(X_1, G2_, x1);

    Fr x2; x2.setByCSPRNG();
    G2 X_2; G2::mul(X_2, G2_, x2);

    G1 G1_;
    mcl::bn::hashAndMapToG1(G1_, "2");
    G1 H1;
    mcl::bn::hashAndMapToG1(H1, "H1");

    // === CL 参数初始化 ===
    SecLevel sec(128);
    RandGen rng;
    CL_HSMqk C(Mpz("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"), 1, sec, rng); // qsize=256 bits, k=1
    auto dk = C.keygen(rng);
    auto ek = C.keygen(dk);
    
    //将 x1 通过 CL 加密
    Mpz rho1 = rng.random_mpz(C.encrypt_randomness_bound());
    Mpz x1_mpz, x1_mpz_recover; 
    utils::fr_to_mpz(x1_mpz, x1);
    CL_HSMqk::CipherText ct_cl_x1 (C, ek, CL_HSMqk::ClearText (C, x1_mpz), rho1);

    //生成 C 和 D
    Fr r, e;
    r.setByCSPRNG();
    e.setByCSPRNG();
    Mpz rho2 = rng.random_mpz(C.encrypt_randomness_bound());

    // R = r·G1_
    G1 R;
    G1::mul(R, G1_, r);

    // CTt = Enc(r·(x2 + e);rho2) 
    Fr k = r * (x2 + e);   // r·(x2 + e)
    Mpz k_mpz;
    utils::fr_to_mpz(k_mpz, k);
    CL_HSMqk::CipherText CTk (C, ek, CL_HSMqk::ClearText (C, k_mpz), rho2);
    // === CTb = (ct_cl_x1)^r * CTt ===
    Mpz r_mpz;
    utils::fr_to_mpz(r_mpz, r);
    CL_HSMqk::CipherText CTa_r (C.scal_ciphertexts (ek, ct_cl_x1, r_mpz, Mpz(0UL)));
    CL_HSMqk::CipherText CTb (C.add_ciphertexts (ek, CTa_r, CTk, Mpz(0UL)));
    

    // === R_DL ===
    auto pi1_DL = RDL::prove("RDL", G2_, X_1, x1);
    std::cout << "[RDL] verify: " << (RDL::verify("RDL", G2_, X_1, pi1_DL) ? "OK" : "FAIL") << std::endl;

    auto pi2_DL = RDL::prove("RDL", G2_, X_2, x2);
    std::cout << "[RDL] verify: " << (RDL::verify("RDL", G2_, X_2, pi2_DL) ? "OK" : "FAIL") << std::endl;

    // === R_CL-DL ===
    auto pi1_CLDL = RCLDL::prove("RCLDL", G2_, X_1, x1, C, ek, dk, ct_cl_x1);
    std::cout << "[RCLDL] verify: "
              << (RCLDL::verify("RCLDL", G2_, X_1, C, ek, ct_cl_x1, pi1_CLDL) ? "OK" : "FAIL")
              << std::endl;
    // // === R_CL-DL2 ===
    // auto pi1_CLDL2 = RCLDL2::prove("RCLDL2", G2_, X_1, x1, C, ek, dk, ct_cl_x1);
    // std::cout << "[RCLDL2] verify: "
    //           << (RCLDL2::verify("RCLDL2", G2_, X_1, C, ek, ct_cl_x1, pi1_CLDL2) ? "OK" : "FAIL")
    //           << std::endl;

    // === R_CL-Lin ===
    auto pi_CLLin = ZK::RCLLIN::prove("RCLLIN", G1_, H1, G2_, C, ek, ct_cl_x1, CTb, R, X_2, r, x2, e, rho2);
    std::cout << "[RCL-LIN] verify: " 
              << (RCLLIN::verify("RCLLIN", G1_, H1, G2_, C, ek, ct_cl_x1, CTb, R, X_2, e, pi_CLLin) ? "OK" : "FAIL") 
              << std::endl;


    // // === R_CL-Lin ===
    // auto pi_CLLin2 = ZK::RCLLIN2::prove("RCLLIN2", G1_, H1, G2_, C, ek, ct_cl_x1, CTb, R, X_2, r, x2, e, rho2);
    // std::cout << "[RCL-LIN2] verify: " 
    //           << (RCLLIN2::verify("RCLLIN2", G1_, H1, G2_, C, ek, ct_cl_x1, CTb, R, X_2, e, pi_CLLin2) ? "OK" : "FAIL") 
    //           << std::endl;


    int ret = ecvrf_test_demo();
    if (ret == 0) {
        printf("VRF test passed.\n");
    } else {
        printf("VRF test failed.\n");
    }
    return 0;

}