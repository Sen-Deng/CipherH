
# CipherH

This is the home of CipherH: Automated Detection of Ciphertext Side-channel Vulnerabilities in Cryptographic Implementations. CipherH is a practical framework for automating the analysis of cryptographic software and detecting program points vulnerable to ciphertext side channels. CipherH is designed to perform a practical hybrid analysis in production cryptographic software, with a speedy dynamic taint analysis to track the usage of secrets throughout the entire program and a static symbolic execution
procedure on each “tainted” function to reason about ciphertext side-channel vulnerabilities using symbolic constraint.

CipherH includes two components: dynamic taint annlysis and static symbolic execution.  This is the high-level architecture of CipherH:


![workflow_00](https://github.com/Sen-Deng/CipherH/assets/114982128/885f5cb7-3d23-44b7-9fda-c0cc6a164b00)



## Dynamic Taint Analysis

The taint analysis module is implemented by extending [constantine](https://github.com/pietroborrello/constantine.git), which is a compiler-based system to automatically harden programs against microarchitectural side channels.

Switch to src directory, compile and install the LLVM passes:

```bash

./install.sh
. ./setup.sh
./llvm_compile_dfsan_cpp.sh
(cd passes && make install)
(cd lib && make install)

```

Switch to /src/apps/wolfssl_case_study, run:

```bash

./build_dft.sh

```
This will produce a instrucmented test.dft.out binary, run test.dft.out and output results into the "taint.txt".  

The source code of different libraries is also provided, and you can run ./extract_bc.sh to get the corresponding .bc files. 


## Tainted Functions

Run 

```bash

python3 process.py

```
The input is the "taint.txt", and the outputs are saved into "tainted_func.txt" and "traced_func.txt".


## Static Symbolic Execution

Install angr in a virtual environment, and run 

```bash

python3 run.py

```
This will output the corresponding vulnerability reports.


## Evaluation Results

Evaluation results for ECDSA/ECDH/RSA implementations of WolfSSL, OpenSSL, and MbedTLS are also provided. The collected vulnerable program points are in the file "result".

If you have any questions, please feel free to contact me directly via 12032873@mail.sustech.edu.cn.
