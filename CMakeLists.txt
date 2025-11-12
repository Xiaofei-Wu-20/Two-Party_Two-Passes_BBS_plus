cmake_minimum_required(VERSION 3.29)
project(Copy_Fei-Multiparty-BBS-Plus-Implementation)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -Wall")

add_subdirectory(include/mcl EXCLUDE_FROM_ALL)
add_subdirectory(include/bicycl EXCLUDE_FROM_ALL)


find_library(GMP_LIBRARY gmp)
find_library(GMPXX_LIBRARY gmpxx)

find_package (OpenSSL REQUIRED)
# find_package (benchmark) #Google Benchmark

file(GLOB CPP_SOURCES  "src/*.cpp")
file(GLOB C_SOURCES "src/*.c")
file(GLOB HEADERS "include/*.h")

set(MAIN_CPP "${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp")
set(TEST_CPP "${CMAKE_CURRENT_SOURCE_DIR}/src/zk_test.cpp")
set(BBS_Benchmark_CPP "${CMAKE_CURRENT_SOURCE_DIR}/src/bbs_benchmark.cpp")
set(SOURCES ${CPP_SOURCES} ${C_SOURCES})

list(REMOVE_ITEM SOURCES ${TEST_CPP} ${BBS_Benchmark_CPP})

add_executable(Two-party_Two_Pass_BBS_Plus_Implementation ${SOURCES} ${HEADERS}
    src/Party1.cpp
    src/Party2.cpp
    src/zk_sigma.cpp
)

target_link_libraries(Two-party_Two_Pass_BBS_Plus_Implementation
        PRIVATE
        mcl
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::Crypto
        OpenSSL::SSL
)

list(REMOVE_ITEM SOURCES ${MAIN_CPP} ${BBS_Benchmark_CPP})
add_executable(zk_test ${SOURCES} ${TEST_CPP} ${HEADERS} )
target_link_libraries(zk_test
    PRIVATE
    mcl
    bicycl
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)

list(REMOVE_ITEM SOURCES ${MAIN_CPP} ${TEST_CPP})
add_executable(bbs_benchmark ${SOURCES} ${BBS_Benchmark_CPP} ${HEADERS} )
target_link_libraries(bbs_benchmark
    PRIVATE
    mcl
    bicycl
    ${GMP_LIBRARY}
    ${GMPXX_LIBRARY}
    OpenSSL::Crypto
    OpenSSL::SSL
)   


