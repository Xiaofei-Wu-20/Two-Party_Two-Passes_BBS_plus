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
    size_t n = 5;
    size_t t = 4;
    size_t ell = 2;

    ProtocolParams params(BLS12_381, SecLevel::_128, n, t, ell, rng);
    Protocol protocol(params);
    protocol.dkg();

    std::set<size_t> party_set = utils::select_parties(rng, n, t);
    std::vector<Fr> messages;
    messages.reserve(ell);
    utils::randomize_messages(messages, ell);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;


    std::vector<Signature> signature_set = protocol.run(party_set, messages);
    bool ret = protocol.verify(signature_set, messages);
    if (ret)
    {
        std::cout << "run success" << std::endl;
    }
    else
    {
        std::cout << "run fail" << std::endl;
    }
    return 0;
}
