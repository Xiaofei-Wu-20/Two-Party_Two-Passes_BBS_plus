#include "../include/mcl/include/mcl/bls12_381.hpp"
#include <chrono>
#include <iostream>
#include <numeric>
#include <vector>
#include <cmath>

using namespace mcl::bn;
using namespace std;
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

// ---------- BBS+ basic operations ----------
struct BBSParams {
    G1 G1_;
    G2 G2_;
    vector<G1> H;
};

// setup generators
void setup(BBSParams& param, size_t l) {
    mapToG1(param.G1_, 1);
    mapToG2(param.G2_, 2);
    param.H.resize(l + 1);
    for (size_t i = 0; i <= l; i++) {
        mapToG1(param.H[i], (int)(100 + i));
    }
}

// key generation
void keyGen(Fr& sk, G2& pk, const BBSParams& param) {
    sk.setRand();
    G2::mul(pk, param.G2_, sk);
}

// sign(m): A = (r*(x+e))^{-1}(G1 + sH1 + sum mi Hi+1)
void sign(G1& A, Fr& e, Fr& s, const vector<Fr>& m, const Fr& sk, const BBSParams& param) {
    Fr r; r.setRand();
    e.setRand(); s.setRand();
    G1 B = param.G1_;
    G1 tmp;
    G1::mul(tmp, param.H[0], s);
    G1::add(B, B, tmp);
    for (size_t i = 0; i < m.size(); i++) {
        G1::mul(tmp, param.H[i + 1], m[i]);
        G1::add(B, B, tmp);
    }
    Fr denom = sk; denom += e; denom *= r;
    Fr inv;
    Fr::inv(inv, denom);
    G1::mul(A, B, inv);
}

// verify: e(A, X + eG2) = e(G1 + sH1 + sum miHi+1, G2)
bool verify(const G1& A, const Fr& e, const Fr& s, const vector<Fr>& m,
            const G2& pk, const BBSParams& param) {
    G1 left = param.G1_;
    G1 tmp;
    G1::mul(tmp, param.H[0], s);
    G1::add(left, left, tmp);
    for (size_t i = 0; i < m.size(); i++) {
        G1::mul(tmp, param.H[i + 1], m[i]);
        G1::add(left, left, tmp);
    }
    G2 Xplus; G2::mul(Xplus, param.G2_, e);
    G2::add(Xplus, pk, Xplus);
    Fp12 e1, e2;
    pairing(e1, A, Xplus);
    pairing(e2, left, param.G2_);
    return e1 == e2;
}

// benchmark helper
template<typename F>
Stats bench(F func, int iter = 100) {
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
    initPairing(mcl::BLS12_381);
    cout << "BBS+ Benchmark (BLS12-381, MCL)\n";

    BBSParams param;
    size_t l = 3; // number of messages
    setup(param, l);

    Fr sk; G2 pk;
    vector<Fr> m(l);
    for (auto &mi : m) mi.setRand();

    // measure G1 mul and G2 mul
    Stats g1stat = bench([&](){ G1 P; Fr k; G1::mul(P, param.G1_, k); });
    Stats g2stat = bench([&](){ G2 Q; Fr k; G2::mul(Q, param.G2_, k); });

    // keygen
    Stats keyStat = bench([&](){ keyGen(sk, pk, param); });


    // sign
    Stats signStat = bench([&](){
        G1 A; Fr e, s; sign(A, e, s, m, sk, param);
    });

    // verify
    Stats verifyStat = bench([&](){
        G1 A; Fr e, s; sign(A, e, s, m, sk, param);
        verify(A, e, s, m, pk, param);
    });

    cout.setf(ios::fixed);
    cout.precision(3);
    cout << "\nOperation\tMean (ms)\tStddev (ms)\n";
    cout << "KeyGen\t\t" << keyStat.mean/1000 << "\t" << keyStat.stddev/1000 << endl;
    cout << "Sign\t\t" << signStat.mean/1000 << "\t" << signStat.stddev/1000 << endl;
    cout << "Verify\t\t" << verifyStat.mean/1000 << "\t" << verifyStat.stddev/1000 << endl;
    cout << "G1 mul\t\t" << g1stat.mean/1000 << "\t" << g1stat.stddev/1000 << endl;
    cout << "G2 mul\t\t" << g2stat.mean/1000 << "\t" << g2stat.stddev/1000 << endl;
}
