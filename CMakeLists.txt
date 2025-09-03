cmake_minimum_required(VERSION 3.29)
project(Three-Round-Multiparty-ECDSA)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall")

add_subdirectory(include/bicycl EXCLUDE_FROM_ALL)

find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)

find_package (OpenSSL REQUIRED)
# find_package (benchmark) #Google Benchmark

file(GLOB SOURCES "src/*.cpp")

file(GLOB HEADERS "include/*.h")

add_executable(Three-Round-Multiparty-ECDSA ${SOURCES} ${HEADERS})

target_link_libraries(Three-Round-Multiparty-ECDSA
        PRIVATE
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)