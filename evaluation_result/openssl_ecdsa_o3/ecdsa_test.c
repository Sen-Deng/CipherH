
// gcc -o ecdsa ecdsa_simple.c -L. -lcrypto -static -ldl -pthread

//compiled with gcc -g -lssl -UOPENSSL_NO_EC SO2228860.c -lcrypto
#include <openssl/ec.h>      // for EC_GROUP_new_by_curve_name, EC_GROUP_free, EC_KEY_new, EC_KEY_set_group, EC_KEY_generate_key, EC_KEY_free
#include <openssl/ecdsa.h>   // for ECDSA_do_sign, ECDSA_do_verify
#include <openssl/obj_mac.h> // for NID_secp192k1
#include <string.h>
#include <sanitizer/dfsan_interface.h>
// Their is a small bug in the above code. The hash that is passed is an unsigned char, this hash CAN have 0x00 values in it! Do NOT use the strlen(hash) to calculate the length, as that will possibly pass the incorrect length to the routine IF the hash has a 0x00 in it anywhere. Hashes are fixed length, and should be passed as such. sha256 for example should be of length 64.
static dfsan_label input_label;

uint32_t OPENSSL_ia32cap_P[4] = { 0 };


static int create_signature(unsigned char* hash)
{
    int function_status = -1;
BIGNUM *priv_key;
input_label = dfsan_create_label("input", 0);
    EC_KEY *eckey=EC_KEY_new();
    // printf("1 private key:(%s)\n", BN_bn2hex(EC_KEY_get0_private_key(eckey)));
    if (NULL == eckey)
    {
        
        function_status = -1;
    }
    else
    {
        EC_GROUP *ecgroup= EC_GROUP_new_by_curve_name(NID_secp256k1); //used for bitcoin
        // printf("2 private key:(%s)\n", BN_bn2hex(EC_KEY_get0_private_key(eckey)));
        if (NULL == ecgroup)
        {
            
            function_status = -1;
        }
        else
        {
            int set_group_status = EC_KEY_set_group(eckey,ecgroup);
            // printf("2 private key:(%s)\n", BN_bn2hex(EC_KEY_get0_private_key(eckey)));
            const int set_group_success = 1;

            if (set_group_success != set_group_status)
            {
                
                function_status = -1;
            }
            else
            {
                const int gen_success = 1;
                int gen_status = EC_KEY_generate_key(eckey);
              
                if (gen_success != gen_status)
                {
                    
                    function_status = -1;
                }
                else
                {   priv_key =  EC_KEY_get0_private_key(eckey);
                 
                    const BIGNUM *sr, *ss;
                   
                     dfsan_set_label(input_label,priv_key , sizeof(priv_key));
                    ECDSA_SIG *signature = ECDSA_do_sign(hash, strlen(hash), eckey);
                    
                    ECDSA_SIG_get0(signature, &sr, &ss);
                 
                    // EC_KEY_get0_public_key()
                
                }
            }
            EC_GROUP_free(ecgroup);
        }
        EC_KEY_free(eckey);
    }

  return function_status;
}

int main( int argc , char * argv[] )
{
    unsigned char hash[] = "c7fbca202a95a570285e3d700eb04ca2";
    int status = create_signature(hash);
    return(0) ;
}

