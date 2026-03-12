# Two-Party_BBS_Plus_Signature_in_Two_Passes_Implementation
This repository provides the C++ implementation of the scheme described in our paper:

"Two-Party BBS+ Signature in Two Passes", accepted by ESORICS 2026. If you use this code in your research, please cite our paper.

## Overview
This project focuses on the performance and efficiency of our two-party BBS+ signature scheme. For comparisons with other State-of-the-Art (SotA) schemes, please refer to the Implementation and Comparison section of our paper, where detailed metrics and environmental setups are provided.

## ✨ Features

* **Two-Party BBS+ Signatures**: Supports collaborative generation of BBS+ signatures between two parties.
* **Extreme Communication Efficiency**: The entire signature generation process requires only two communication passes.
* **No Single Point of Trust**: The protocol design completely removes the reliance on a trusted third-party.
* **Strong Security Guarantees**: Built upon rigorous CL-encryption and Non-interactive zero-knowledge proofs (NIZK).
* **Performance-Oriented**: Provides comprehensive benchmarking tests to evaluate its practical execution efficiency.

## 📂 Repository Structure

* `src/`: Contains the source code for the core protocol logic, security primitives, and benchmarking tests.
* `include/`: C++ header files required for the project.
* `build/`: Default directory for build outputs.
* `CMakeLists.txt`: CMake build configuration file.
* `Dockerfile`: Docker image configuration for quickly setting up a standardized build and runtime environment.
* `build.sh`: Automated build script to simplify the compilation process.

## 🛠️ Build and Run

This project is primarily developed in C++ and uses CMake as its build system.

### Method 1: Using Docker (Recommended)
To avoid tedious environment setup, a `Dockerfile` is provided. You can directly build and run the container:

```bash
git clone [https://github.com/Xiaofei-Wu-20/Two-Party_Two-Passes_BBS_plus.git](https://github.com/Xiaofei-Wu-20/Two-Party_Two-Passes_BBS_plus.git)
cd Two-Party_Two-Passes_BBS_plus
docker build -t bbs_plus .
docker run -it bbs_plus /bin/bash
```

### Method 2: Local Build

Ensure your system has a `C++ compiler`, `CMake`, and relevant fundamental cryptographic libraries installed (such as GMP, OpenSSL, etc., depending on specific code dependencies).

```bash
git clone [https://github.com/Xiaofei-Wu-20/Two-Party_Two-Passes_BBS_plus.git](https://github.com/Xiaofei-Wu-20/Two-Party_Two-Passes_BBS_plus.git)
cd Two-Party_Two-Passes_BBS_plus

# Run the automated build script
chmod +x build.sh
./build.sh
```
