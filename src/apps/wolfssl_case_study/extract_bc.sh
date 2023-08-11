#!/bin/sh

# make sure to have a recent objcopy version in the PATH (like 2.35)

set -e
set -x

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

export PATH=$PATH:/usr/local/go/bin
export LLVM_BITCODE_GENERATION_FLAGS="-flto"

cd ../wolfssl



CC=clang CXX=clang++ CFLAGS="-DWC_PROTECT_ENCRYPTED_MEM -O2"  ./configure  --enable-pwdbased  --disable-dh --enable-ecc --disable-asm --enable-static
make
sudo make install
make clean

WLLVM_CONFIGURE_ONLY=1 CC=gclang CXX=gclang++ CFLAGS="-DWC_PROTECT_ENCRYPTED_MEM -O2" ./configure  --disable-dh --enable-ecc --disable-asm --enable-static
make




#CC=clang CXX=clang++ CFLAGS="-O3" ./Configure no-asm
#make
#sudo make install
#make clean

#WLLVM_CONFIGURE_ONLY=1 CC=gclang CXX=gclang++ CFLAGS="-O3" ./Configure no-asm
#make




# make CC=clang CXX=clang++ CFLAGS="-O2 -m32"
# sudo make install
# make clean

# make  SHARED=1 CC=gclang CXX=gclang++ CFLAGS="-O2 -m32"
# sudo make install



get-bc -b -o wolfssl.bc ./src/.libs/libwolfssl.so.33.0.0
cp wolfssl.bc ../wolfssl_case_study

#get-bc -b -o crypto.bc ./libcrypto.so.3
#cp crypto.bc ../wolfssl_case_study

# get-bc -b -o mbedcrypto.bc /usr/local/lib/libmbedcrypto.so.11
# cp mbedcrypto.bc ../wolfssl_case_study
