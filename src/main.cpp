#include "../include/global_context.h"
#include "../include/Party1.h"
#include "../include/Party2.h"
#include "../include/Utils.h"
#include <openssl/sha.h>
#include <iostream>
#include <vector>

#include <cmath>
#include <chrono>
#include <numeric>

using namespace mcl;
using namespace std;
using namespace BICYCL;

using namespace chrono;


struct Stats {
    double mean, stddev;
};
Stats analyze(const vector<double>& v) {
    double sum = accumulate(v.begin(), v.end(), 0.0);
    double mean = sum / v.size();
    double accum = 0.0;
    for (auto& x : v) accum += (x - mean) * (x - mean);
    return {mean, sqrt(accum / (v.size() - 1))};
}

// benchmark helper
template<typename F>
Stats bench(F func, int iter = 10) {
    vector<double> res;
    for (int i = 0; i < iter; i++) {
        auto t1 = high_resolution_clock::now();
        func();
        auto t2 = high_resolution_clock::now();
        double dt = duration_cast<duration<double, std::micro>>(t2 - t1).count(); // µs
        res.push_back(dt);
    }
    return analyze(res);
}

int main() {
    // try {
        // === Step 0: Initialize global environment ===
        GlobalContext::init();
        // std::cout << "=== Two-Party BBS+ Signature Protocol Test ===" << std::endl;
        // === Step 1: Run DKG ===
        Party1 P1;
        Party2 P2;
    Stats keyStat = bench([&](){
        auto m1 = P1.round1();
        auto m2 = P2.round2(m1);
        auto m3 = P1.round3(m2);
        P2.finalize(m3, m1);
    });
        // std::cout << "[Main] DKG completed successfully!\n";

        // === Step 2: Prepare messages ===
        const size_t ell = GlobalContext::Environment::bbs_ell;
        std::vector<mcl::bn::Fr> messages;
        for (size_t i = 0; i < ell; ++i) {
            mcl::bn::Fr mi;
            mi.setByCSPRNG();
            messages.push_back(mi);
        }
        P1.setMessages(messages);
        P2.setMessages(messages);
        // std::cout << "[Main] Generated " << ell << " random messages.\n";

        // === Step 3: Run signing ===
        // std::cout << "\n[Main] === Start Signing ===\n";
    Stats signStat = bench([&](){
        auto msg_sign_p1_to_p2 = P1.sign_pass1();
        auto msg_sign_p2_to_p1 = P2.sign_pass2(msg_sign_p1_to_p2);
        P1.sign_output(msg_sign_p2_to_p1); 
    });
        // std::cout << "\n[Main] Signing completed successfully!\n";

        // // === Step 4: Output final signature ===
        // if (P1.BBS_Plus_signature) {
        //     const auto &sig = *P1.BBS_Plus_signature;
        //     std::cout << "\n=== Final BBS+ Signature ===" << std::endl;
        //     std::cout << "A = " << sig.A << std::endl;
        //     std::cout << "e = " << sig.e << std::endl;
        //     std::cout << "s = " << sig.s << std::endl;
        // } else {
        //     std::cout << "[Main] No signature was produced.\n";
        // }
        // std::cout << "\n=== Protocol completed successfully ===" << std::endl;

        cout.setf(ios::fixed);
        cout.precision(3);
        cout << "\nOperation\tMean (ms)\tStddev (ms)\n";
        cout << "KeyGen\t\t" << keyStat.mean/1000 << "\t" << keyStat.stddev/1000 << endl;
        cout << "Sign\t\t" << signStat.mean/1000 << "\t" << signStat.stddev/1000 << endl;
    // }
    // catch (const std::exception &ex) {
    //     std::cerr << "\n[Error] Exception: " << ex.what() << std::endl;
    //     return 1;
    // }

    return 0;
}
