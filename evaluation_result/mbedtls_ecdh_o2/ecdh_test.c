/*
 *  Example ECDHE with Curve25519 program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include "mbedtls/build_info.h"
#include <sanitizer/dfsan_interface.h>
#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdio.h>
#include <stdlib.h>
#define mbedtls_printf          printf
#define mbedtls_exit            exit
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE
#endif /* MBEDTLS_PLATFORM_C */


#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ecdh.h"

static dfsan_label input_label;
int main( int argc, char *argv[] )
{ input_label = dfsan_create_label("input", 0);
    int ret = 1;
    int exit_code = MBEDTLS_EXIT_FAILURE;
    mbedtls_ecdh_context ctx_cli, ctx_srv;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    unsigned char cli_to_srv[32], srv_to_cli[32];
    const char pers[] = "ecdh";
    ((void) argc);
    ((void) argv);

    mbedtls_ecdh_init( &ctx_cli );
    mbedtls_ecdh_init( &ctx_srv );
    mbedtls_ctr_drbg_init( &ctr_drbg );

    /*
     * Initialize random number generation
     */
 
    fflush( stdout );

    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               sizeof pers ) ) != 0 )
    {
      
        goto exit;
    }

  

    /*
     * Client: initialize context and generate keypair
     */
 
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_cli.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
       
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_cli.MBEDTLS_PRIVATE(grp), &ctx_cli.MBEDTLS_PRIVATE(d), &ctx_cli.MBEDTLS_PRIVATE(Q),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
       
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_cli.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), cli_to_srv, 32 );
    if( ret != 0 )
    {
      
        goto exit;
    }

   

    /*
     * Server: initialize context and generate keypair
     */
   
    fflush( stdout );

    ret = mbedtls_ecp_group_load( &ctx_srv.MBEDTLS_PRIVATE(grp), MBEDTLS_ECP_DP_CURVE25519 );
    if( ret != 0 )
    {
      
        goto exit;
    }

    ret = mbedtls_ecdh_gen_public( &ctx_srv.MBEDTLS_PRIVATE(grp), &ctx_srv.MBEDTLS_PRIVATE(d), &ctx_srv.MBEDTLS_PRIVATE(Q),
                                   mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
      
        goto exit;
    }

    ret = mbedtls_mpi_write_binary( &ctx_srv.MBEDTLS_PRIVATE(Q).MBEDTLS_PRIVATE(X), srv_to_cli, 32 );
    if( ret != 0 )
    {
       
        goto exit;
    }

  
    /*
     * Server: read peer's key and generate shared secret
     */
    
    fflush( stdout );

    ret = mbedtls_mpi_lset( &ctx_srv.MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(Z), 1 );
    if( ret != 0 )
    {
     
        goto exit;
    }

    ret = mbedtls_mpi_read_binary( &ctx_srv.MBEDTLS_PRIVATE(Qp).MBEDTLS_PRIVATE(X), cli_to_srv, 32 );
    if( ret != 0 )
    {
     
        goto exit;
    }
    dfsan_set_label(input_label, &ctx_srv, sizeof(ctx_srv));
    ret = mbedtls_ecdh_compute_shared( &ctx_srv.MBEDTLS_PRIVATE(grp), &ctx_srv.MBEDTLS_PRIVATE(z),
                                       &ctx_srv.MBEDTLS_PRIVATE(Qp), &ctx_srv.MBEDTLS_PRIVATE(d),
                                       mbedtls_ctr_drbg_random, &ctr_drbg );
    if( ret != 0 )
    {
        
        goto exit;
    }

    mbedtls_printf( " ok\n" );

 
    exit_code = MBEDTLS_EXIT_SUCCESS;

exit:



    mbedtls_ecdh_free( &ctx_srv );
    mbedtls_ecdh_free( &ctx_cli );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );

    mbedtls_exit( exit_code );
}

