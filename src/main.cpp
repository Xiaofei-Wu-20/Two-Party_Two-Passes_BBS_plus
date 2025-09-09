#include <sstream>
#include <iostream>
#include <chrono>

#include <vector>
#include <string>

#include "../include/Protocol.h"
#include "../include/threshold_elgamal.h"

using namespace mcl;
using namespace std;
using namespace BICYCL;

int main() {

    RandGen rng;
    size_t n = 20;
    size_t t = 19;
    size_t ell = 2;

    ProtocolParams params(BLS12_381, SecLevel::_128, n, t, ell, rng);
    Protocol protocol(params);
    protocol.dkg();

    std::set<size_t> party_set = utils::select_parties(rng, n, t);
    std::vector<Fr> messages(ell);
    utils::randomize_messages(messages, ell);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<Signature*> signature_set(party_set.size(), nullptr);
    protocol.run(party_set, messages, signature_set);
    auto end = std::chrono::high_resolution_clock::now();

    bool ret = protocol.verify(signature_set, messages);
    if (ret)
    {
        std::chrono::duration<double> duration = end - start;
        std::cout << "run success in " << duration.count() / static_cast<double>(t+1) << " s" << std::endl;
    }
    else
    {
        std::cout << "run fail" << std::endl;
    }

    for(Signature* ptr : signature_set) {
        delete ptr;
    }

    return 0;
}
