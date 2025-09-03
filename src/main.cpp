#include <sstream>
#include <iostream>
#include <chrono>

#include "../include/Protocol.h"

using namespace BICYCL;

int main()
{
    RandGen rng;
    size_t n = 5;
    size_t t = 4;

    GroupParams params(SecLevel::_128, n, t, rng);

    Protocol protocol(params);
    protocol.dkg();

    std::set<size_t> party_set = select_parties(rng, n, t);
    std::vector<unsigned char> message;
    randomize_message(message);

    std::cout << "Selected parties: ";
    for (const auto& id : party_set) {
        std::cout << id << " ";
    }
    std::cout << std::endl;

    /**************** NDSS24 Test ******************/
    NDSS24 data(rng, SecLevel::_128);
    size_t num = data.getSize();
    std::cout << "total:" << num / 1024.0 << std::endl;
    std::cout << "Ideal Size of Communication(KBytes): 17 | 35 | 50 | 67 |" << std::endl;
    std::vector<int> test_n = {5, 10, 15, 20};
    std::cout << "NDSS24 Size of Communication(KBytes): ";
    for(size_t i = 0; i < test_n.size(); ++i)
    {
        std::cout << static_cast<double>(num) * (test_n[i] - 1) / 1024.0 << " | ";
    }
    std::cout << std::endl;

    /**************** TECDSA Test ******************/
    std::cout << "TECDSA Size of Communication(KBytes): ";
    for(int i = 0; i < test_n.size(); ++i)
    {
        std::cout << static_cast<double>((sizeof(TECDSA)) * (test_n[i] - 1)) / 1024.0 << " | ";
        // std::cout << "Size of Communication: " << static_cast<double>((sizeof(RoundOneData) + sizeof(RoundTwoData) + sizeof(RoundThreeData) ) * (n - 1)) / 1024.0 << " KBytes" << std::endl;
    }
    std::cout << std::endl;

    auto start = std::chrono::high_resolution_clock::now();
    std::vector<Signature> signature_set = protocol.run(party_set, message);
    auto end = std::chrono::high_resolution_clock::now();

    bool ret = protocol.verify(signature_set, message);
    if (ret)
    {
        std::chrono::duration<double> duration = end - start;
        std::cout << "run success in " << duration.count() / static_cast<double>(n) << " s" << std::endl;
    }
    else
    {
        std::cout << "run fail" << std::endl;
    }


    return 0;
}