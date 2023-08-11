#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/ssl.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <sanitizer/dfsan_interface.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/signature.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/error-crypt.h>


#define HEAP_HINT NULL
#define KEY32 32
#define BYTE_SZ 8
#define check(ret) assert(!(ret))

static dfsan_label input_label;

mp_int my_key;

int main(int argc, char* argv[])
{
    int     ret = 0;
    ecc_key     key2, key3;
    WC_RNG      rng;
    ecc_point G, R;
    mp_int a, mod;

    input_label = dfsan_create_label("input", 0);

    check(wc_ecc_init(&key2));
    check(wc_ecc_init(&key3));

    char* Gx = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    char* Gy = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5";
    char* Af = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC";
    char* Se = "5B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    char* prime = "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF";

    check(wc_ecc_import_raw_ex(&key2, Gx, Gy, Se, ECC_SECP256R1));
    //check(wc_ecc_import_raw_ex(&key3, Gx, Gy, prime, ECC_SECP256R1));

#define INPUT_SIZE 32
    
    dfsan_set_label(input_label, &key2, sizeof(key2));

    //mp_init_copy(&mod, &key3.k);

    //check(wc_ecc_mulmod(&key2.k, &G, &R, &a, &mod, 0));

    unsigned char hash[32] = {
                                0x3b, 0x07, 0x54, 0x5c, 0xfd, 0x4f, 0xb7, 0xb5,
                               0xaf, 0xa7, 0x7a, 0x25, 0x33, 0xa5, 0x50, 0x70,
                               0x4a, 0x65, 0x3e, 0x72, 0x7e, 0xcd, 0xd4, 0x5b,
                               0x1b, 0x36, 0x96, 0x96, 0xca, 0x4f, 0x9b, 0x6f
                              };

    byte* sig = NULL;
    int verified = 0;
    int byteField = (256 + (BYTE_SZ - 1)) / BYTE_SZ;
    word32 maxSigSz = ECC_MAX_SIG_SIZE;

    sig = (byte*) XMALLOC(maxSigSz * sizeof(byte), NULL,
                          DYNAMIC_TYPE_TMP_BUFFER);

    wc_InitRng(&rng);
    dfsan_set_label(input_label, &rng, sizeof(rng));
    wc_ecc_sign_hash(hash, sizeof(hash), sig, &maxSigSz, &rng, &key2);

   
rng_done:
    wc_FreeRng(&rng);

sig_done:
    XFREE(sig, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    wc_ecc_free(&key2);
    wc_ecc_free(&key3);
    return ret;
}
