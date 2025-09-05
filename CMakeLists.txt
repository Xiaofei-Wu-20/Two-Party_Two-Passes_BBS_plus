cmake_minimum_required(VERSION 3.29)
project(Multiparty-BBS-Plus-Implementation)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall")

add_subdirectory(include/mcl EXCLUDE_FROM_ALL)
add_subdirectory(include/bicycl EXCLUDE_FROM_ALL)

find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)

find_package (OpenSSL REQUIRED)
# find_package (benchmark) #Google Benchmark

file(GLOB SOURCES "src/*.cpp")

file(GLOB HEADERS "include/*.h")

add_executable(Multiparty-BBS-Plus-Implementation ${SOURCES} ${HEADERS}
        include/threshold_elgamal.h
        include/protocol_types.h
)

target_link_libraries(Multiparty-BBS-Plus-Implementation
        PRIVATE
        mcl
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)