/* wc_port.h
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

/*!
    \file wolfssl/wolfcrypt/wc_port.h
*/

#ifndef WOLF_CRYPT_PORT_H
#define WOLF_CRYPT_PORT_H

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/visibility.h>

#ifdef __cplusplus
    extern "C" {
#endif

/* Detect if compiler supports C99. "NO_WOLF_C99" can be defined in
 * user_settings.h to disable checking for C99 support. */
#if !defined(WOLF_C99) && defined(__STDC_VERSION__) && \
    !defined(WOLFSSL_ARDUINO) && !defined(NO_WOLF_C99)
    #if __STDC_VERSION__ >= 199901L
        #define WOLF_C99
    #endif
#endif


/* GENERIC INCLUDE SECTION */
#if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #include <mqx.h>
    #if (defined(MQX_USE_IO_OLD) && MQX_USE_IO_OLD) || \
        defined(FREESCALE_MQX_5_0)
        #include <fio.h>
    #else
        #include <nio.h>
    #endif
#endif

#ifdef WOLFSSL_LINUXKM
    #include "../../linuxkm/linuxkm_wc_port.h"
#endif /* WOLFSSL_LINUXKM */

/* THREADING/MUTEX SECTION */
#ifdef USE_WINDOWS_API
    #ifdef WOLFSSL_GAME_BUILD
        #include "system/xtl.h"
    #else
        #ifndef WIN32_LEAN_AND_MEAN
            #define WIN32_LEAN_AND_MEAN
        #endif
        #ifndef WOLFSSL_SGX
            #if defined(_WIN32_WCE) || defined(WIN32_LEAN_AND_MEAN)
                /* On WinCE winsock2.h must be included before windows.h */
                #include <winsock2.h>
            #endif
            #include <windows.h>
            #ifndef WOLFSSL_USER_IO
                #include <ws2tcpip.h> /* required for InetPton */
            #endif
        #endif /* WOLFSSL_SGX */
    #endif
#elif defined(THREADX)
    #ifndef SINGLE_THREADED
        #ifdef NEED_THREADX_TYPES
            #include <types.h>
        #endif
        #include <tx_api.h>
    #endif
#elif defined(WOLFSSL_DEOS)
    #include "mutexapi.h"
#elif defined(MICRIUM)
    /* do nothing, just don't pick Unix */
#elif defined(FREERTOS) || defined(FREERTOS_TCP) || defined(WOLFSSL_SAFERTOS)
    /* do nothing */
#elif defined(RTTHREAD)
    /* do nothing */
#elif defined(EBSNET)
    /* do nothing */
#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    /* do nothing */
#elif defined(FREESCALE_FREE_RTOS)
    #include "fsl_os_abstraction.h"
#elif defined(WOLFSSL_VXWORKS)
    #include <semLib.h>
#elif defined(WOLFSSL_uITRON4)
    #include "stddef.h"
    #include "kernel.h"
#elif  defined(WOLFSSL_uTKERNEL2)
    #include "tk/tkernel.h"
#elif defined(WOLFSSL_CMSIS_RTOS)
    #include "cmsis_os.h"
#elif defined(WOLFSSL_CMSIS_RTOSv2)
    #include "cmsis_os2.h"
#elif defined(WOLFSSL_MDK_ARM)
    #if defined(WOLFSSL_MDK5)
        #include "cmsis_os.h"
    #else
        #include <rtl.h>
    #endif
#elif defined(WOLFSSL_CMSIS_RTOS)
    #include "cmsis_os.h"
#elif defined(WOLFSSL_TIRTOS)
    #include <ti/sysbios/BIOS.h>
    #include <ti/sysbios/knl/Semaphore.h>
#elif defined(WOLFSSL_FROSTED)
    #include <semaphore.h>
#elif defined(INTIME_RTOS)
    #include <rt.h>
    #include <io.h>
#elif defined(WOLFSSL_NUCLEUS_1_2)
    /* NU_DEBUG needed struct access in nucleus_realloc */
    #define NU_DEBUG
    #include "plus/nucleus.h"
    #include "nucleus.h"
#elif defined(WOLFSSL_APACHE_MYNEWT)
    /* do nothing */
#elif defined(WOLFSSL_ZEPHYR)
    #ifndef SINGLE_THREADED
        #include <kernel.h>
    #endif
#elif defined(WOLFSSL_TELIT_M2MB)

    /* Telit SDK uses C++ compile option (--cpp), which causes link issue
        to API's if wrapped in extern "C" */
    #ifdef __cplusplus
        }  /* extern "C" */
    #endif

    #include "m2mb_types.h"
    #include "m2mb_os_types.h"
    #include "m2mb_os_api.h"
    #include "m2mb_os.h"
    #include "m2mb_os_mtx.h"
    #ifndef NO_ASN_TIME
    #include "m2mb_rtc.h"
    #endif
    #ifndef NO_FILESYSTEM
    #include "m2mb_fs_posix.h"
    #endif

    #undef kB /* eliminate conflict in asn.h */

    #ifdef __cplusplus
        extern "C" {
    #endif

#else
    #ifndef SINGLE_THREADED
        #ifndef WOLFSSL_USER_MUTEX
            #ifdef WOLFSSL_LINUXKM
                /* definitions are in linuxkm/linuxkm_wc_port.h */
            #else
                #define WOLFSSL_PTHREADS
                #include <pthread.h>
            #endif
        #endif
    #endif
    #if (defined(OPENSSL_EXTRA) || defined(GOAHEAD_WS)) && \
        !defined(NO_FILESYSTEM)
        #ifdef FUSION_RTOS
            #include <fclunistd.h>
        #else
            #include <unistd.h>      /* for close of BIO */
        #endif
    #endif
#endif

/* For FIPS keep the function names the same */
#ifdef HAVE_FIPS
#define wc_InitMutex   InitMutex
#define wc_FreeMutex   FreeMutex
#define wc_LockMutex   LockMutex
#define wc_UnLockMutex UnLockMutex
#endif /* HAVE_FIPS */

#ifdef SINGLE_THREADED
    typedef int wolfSSL_Mutex;
#else /* MULTI_THREADED */
    /* FREERTOS comes first to enable use of FreeRTOS Windows simulator only */
    #if defined(FREERTOS)
        typedef xSemaphoreHandle wolfSSL_Mutex;
    #elif defined(FREERTOS_TCP)
        #include "FreeRTOS.h"
        #include "semphr.h"
        typedef SemaphoreHandle_t  wolfSSL_Mutex;
    #elif defined (RTTHREAD)
        #include "rtthread.h"
        typedef rt_mutex_t wolfSSL_Mutex;
    #elif defined(WOLFSSL_SAFERTOS)
        typedef struct wolfSSL_Mutex {
            signed char mutexBuffer[portQUEUE_OVERHEAD_BYTES];
            xSemaphoreHandle mutex;
        } wolfSSL_Mutex;
    #elif defined(USE_WINDOWS_API)
        typedef CRITICAL_SECTION wolfSSL_Mutex;
    #elif defined(WOLFSSL_PTHREADS)
        typedef pthread_mutex_t wolfSSL_Mutex;
    #elif defined(WOLFSSL_KTHREADS)
        typedef struct mutex wolfSSL_Mutex;
    #elif defined(THREADX)
        typedef TX_MUTEX wolfSSL_Mutex;
    #elif defined(WOLFSSL_DEOS)
        typedef mutex_handle_t wolfSSL_Mutex;
    #elif defined(MICRIUM)
        typedef OS_MUTEX wolfSSL_Mutex;
    #elif defined(EBSNET)
        typedef RTP_MUTEX wolfSSL_Mutex;
    #elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
        typedef MUTEX_STRUCT wolfSSL_Mutex;
    #elif defined(FREESCALE_FREE_RTOS)
        typedef mutex_t wolfSSL_Mutex;
    #elif defined(WOLFSSL_VXWORKS)
        typedef SEM_ID wolfSSL_Mutex;
    #elif defined(WOLFSSL_uITRON4)
        typedef struct wolfSSL_Mutex {
            T_CSEM sem ;
            ID     id ;
        } wolfSSL_Mutex;
    #elif defined(WOLFSSL_uTKERNEL2)
        typedef struct wolfSSL_Mutex {
            T_CSEM sem ;
            ID     id ;
        } wolfSSL_Mutex;
    #elif defined(WOLFSSL_MDK_ARM)
        #if defined(WOLFSSL_CMSIS_RTOS)
            typedef osMutexId wolfSSL_Mutex;
        #else
            typedef OS_MUT wolfSSL_Mutex;
        #endif
    #elif defined(WOLFSSL_CMSIS_RTOS)
        typedef osMutexId wolfSSL_Mutex;
    #elif defined(WOLFSSL_CMSIS_RTOSv2)
        typedef osMutexId_t wolfSSL_Mutex;
    #elif defined(WOLFSSL_TIRTOS)
        typedef ti_sysbios_knl_Semaphore_Handle wolfSSL_Mutex;
    #elif defined(WOLFSSL_FROSTED)
        typedef mutex_t * wolfSSL_Mutex;
    #elif defined(INTIME_RTOS)
        typedef RTHANDLE wolfSSL_Mutex;
    #elif defined(WOLFSSL_NUCLEUS_1_2)
        typedef NU_SEMAPHORE wolfSSL_Mutex;
    #elif defined(WOLFSSL_ZEPHYR)
        typedef struct k_mutex wolfSSL_Mutex;
    #elif defined(WOLFSSL_TELIT_M2MB)
        typedef M2MB_OS_MTX_HANDLE wolfSSL_Mutex;
    #elif defined(WOLFSSL_USER_MUTEX)
        /* typedef User_Mutex wolfSSL_Mutex; */
    #elif defined(WOLFSSL_LINUXKM)
        /* definitions are in linuxkm/linuxkm_wc_port.h */
    #else
        #error Need a mutex type in multithreaded mode
    #endif /* USE_WINDOWS_API */
#endif /* SINGLE_THREADED */

/* Enable crypt HW mutex for Freescale MMCAU, PIC32MZ or STM32 */
#if defined(FREESCALE_MMCAU) || defined(WOLFSSL_MICROCHIP_PIC32MZ) || \
    defined(STM32_CRYPTO) || defined(STM32_HASH) || defined(STM32_RNG)
    #ifndef WOLFSSL_CRYPT_HW_MUTEX
        #define WOLFSSL_CRYPT_HW_MUTEX  1
    #endif
#endif /* FREESCALE_MMCAU */

#ifndef WOLFSSL_CRYPT_HW_MUTEX
    #define WOLFSSL_CRYPT_HW_MUTEX  0
#endif

#if WOLFSSL_CRYPT_HW_MUTEX
    /* wolfSSL_CryptHwMutexInit is called on first wolfSSL_CryptHwMutexLock,
       however it's recommended to call this directly on Hw init to avoid possible
       race condition where two calls to wolfSSL_CryptHwMutexLock are made at
       the same time. */
    int wolfSSL_CryptHwMutexInit(void);
    int wolfSSL_CryptHwMutexLock(void);
    int wolfSSL_CryptHwMutexUnLock(void);
#else
    /* Define stubs, since HW mutex is disabled */
    #define wolfSSL_CryptHwMutexInit()      0 /* Success */
    #define wolfSSL_CryptHwMutexLock()      0 /* Success */
    #define wolfSSL_CryptHwMutexUnLock()    (void)0 /* Success */
#endif /* WOLFSSL_CRYPT_HW_MUTEX */

/* Mutex functions */
WOLFSSL_API int wc_InitMutex(wolfSSL_Mutex* m);
WOLFSSL_API wolfSSL_Mutex* wc_InitAndAllocMutex(void);
WOLFSSL_API int wc_FreeMutex(wolfSSL_Mutex* m);
WOLFSSL_API int wc_LockMutex(wolfSSL_Mutex* m);
WOLFSSL_API int wc_UnLockMutex(wolfSSL_Mutex* m);
#if defined(OPENSSL_EXTRA) || defined(HAVE_WEBSERVER)
/* dynamically set which mutex to use. unlock / lock is controlled by flag */
typedef void (mutex_cb)(int flag, int type, const char* file, int line);

WOLFSSL_API int wc_LockMutex_ex(int flag, int type, const char* file, int line);
WOLFSSL_API int wc_SetMutexCb(mutex_cb* cb);
#endif

/* main crypto initialization function */
WOLFSSL_API int wolfCrypt_Init(void);
WOLFSSL_API int wolfCrypt_Cleanup(void);

#ifdef WOLFSSL_TRACK_MEMORY_VERBOSE
    WOLFSSL_API long wolfCrypt_heap_peakAllocs_checkpoint(void);
    WOLFSSL_API long wolfCrypt_heap_peakBytes_checkpoint(void);
#endif


/* FILESYSTEM SECTION */
/* filesystem abstraction layer, used by ssl.c */
#ifndef NO_FILESYSTEM

#if defined(EBSNET)
    #include "vfapi.h"
    #include "vfile.h"

    int ebsnet_fseek(int a, long b, int c); /* Not prototyped in vfile.h per
                                             * EBSnet feedback */

    #define XFILE                    int
    #define XFOPEN(NAME, MODE)       vf_open((const char *)NAME, VO_RDONLY, 0)
    #define XFSEEK                   ebsnet_fseek
    #define XFTELL                   vf_tell
    #define XREWIND                  vf_rewind
    #define XFREAD(BUF, SZ, AMT, FD) vf_read(FD, BUF, SZ*AMT)
    #define XFWRITE(BUF, SZ, AMT, FD) vf_write(FD, BUF, SZ*AMT)
    #define XFCLOSE                  vf_close
    #define XSEEK_END                VSEEK_END
    #define XBADFILE                 -1
    #define XFGETS(b,s,f)            -2 /* Not ported yet */

#elif defined(LSR_FS)
    #include <fs.h>
    #define XFILE                   struct fs_file*
    #define XFOPEN(NAME, MODE)      fs_open((char*)NAME)
    #define XFSEEK(F, O, W)         (void)F
    #define XFTELL(F)               (F)->len
    #define XREWIND(F)              (void)F
    #define XFREAD(BUF, SZ, AMT, F) fs_read(F, (char*)BUF, SZ*AMT)
    #define XFWRITE(BUF, SZ, AMT, F) fs_write(F, (char*)BUF, SZ*AMT)
    #define XFCLOSE                 fs_close
    #define XSEEK_END               0
    #define XBADFILE                NULL
    #define XFGETS(b,s,f)           -2 /* Not ported yet */

#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #define XFILE                   MQX_FILE_PTR
    #define XFOPEN                  fopen
    #define XFSEEK                  fseek
    #define XFTELL                  ftell
    #define XREWIND(F)              fseek(F, 0, IO_SEEK_SET)
    #define XFREAD                  fread
    #define XFWRITE                 fwrite
    #define XFCLOSE                 fclose
    #define XSEEK_END               IO_SEEK_END
    #define XBADFILE                NULL
    #define XFGETS                  fgets

#elif defined(WOLFSSL_DEOS)
    #define NO_FILESYSTEM
    #warning "TODO - DDC-I Certifiable Fast File System for Deos is not integrated"
#elif defined(MICRIUM)
    #include <fs_api.h>
    #define XFILE      FS_FILE*
    #define XFOPEN     fs_fopen
    #define XFSEEK     fs_fseek
    #define XFTELL     fs_ftell
    #define XREWIND    fs_rewind
    #define XFREAD     fs_fread
    #define XFWRITE    fs_fwrite
    #define XFCLOSE    fs_fclose
    #define XSEEK_END  FS_SEEK_END
    #define XBADFILE   NULL
    #define XFGETS(b,s,f) -2 /* Not ported yet */

#elif defined(WOLFSSL_NUCLEUS_1_2)
    #include "fal/inc/fal.h"
    #define XFILE      FILE*
    #define XFOPEN     fopen
    #define XFSEEK     fseek
    #define XFTELL     ftell
    #define XREWIND    rewind
    #define XFREAD     fread
    #define XFWRITE    fwrite
    #define XFCLOSE    fclose
    #define XSEEK_END  PSEEK_END
    #define XBADFILE   NULL

#elif defined(WOLFSSL_APACHE_MYNEWT)
    #include <fs/fs.h>
    #define XFILE  struct fs_file*

    #define XFOPEN     mynewt_fopen
    #define XFSEEK     mynewt_fseek
    #define XFTELL     mynewt_ftell
    #define XREWIND    mynewt_rewind
    #define XFREAD     mynewt_fread
    #define XFWRITE    mynewt_fwrite
    #define XFCLOSE    mynewt_fclose
    #define XSEEK_END  2
    #define XBADFILE   NULL
    #define XFGETS(b,s,f) -2 /* Not ported yet */

#elif defined(WOLFSSL_ZEPHYR)
    #include <fs.h>

    #define XFILE      struct fs_file_t*
    #define STAT       struct fs_dirent

    XFILE z_fs_open(const char* filename, const char* perm);
    int z_fs_close(XFILE file);

    #define XFOPEN              z_fs_open
    #define XFCLOSE             z_fs_close
    #define XFSEEK              fs_seek
    #define XFTELL              fs_tell
    #define XFREWIND            fs_rewind
    #define XREWIND(F)          fs_seek(F, 0, FS_SEEK_SET)
    #define XFREAD(P,S,N,F)     fs_read(F, P, S*N)
    #define XFWRITE(P,S,N,F)    fs_write(F, P, S*N)
    #define XSEEK_END           FS_SEEK_END
    #define XBADFILE            NULL
    #define XFGETS(b,s,f)       -2 /* Not ported yet */

#elif defined(WOLFSSL_TELIT_M2MB)
    #define XFILE                    INT32
    #define XFOPEN(NAME, MODE)       m2mb_fs_open((NAME), 0, (MODE))
    #define XFSEEK(F, O, W)          m2mb_fs_lseek((F), (O), (W))
    #define XFTELL(F)                m2mb_fs_lseek((F), 0, M2MB_SEEK_END)
    #define XREWIND(F)               (void)F
    #define XFREAD(BUF, SZ, AMT, F)  m2mb_fs_read((F), (BUF), (SZ)*(AMT))
    #define XFWRITE(BUF, SZ, AMT, F) m2mb_fs_write((F), (BUF), (SZ)*(AMT))
    #define XFCLOSE                  m2mb_fs_close
    #define XSEEK_END                M2MB_SEEK_END
    #define XBADFILE                 -1
    #define XFGETS(b,s,f)            -2 /* Not ported yet */

#elif defined (WOLFSSL_XILINX)
    #include "xsdps.h"
    #include "ff.h"

    /* workaround to declare variable and provide type */
    #define XFILE                    FIL curFile; FIL*
    #define XFOPEN(NAME, MODE)       ({ FRESULT res; res = f_open(&curFile, (NAME), (FA_OPEN_ALWAYS | FA_WRITE | FA_READ)); (res == FR_OK) ? &curFile : NULL; })
    #define XFSEEK(F, O, W)          f_lseek((F), (O))
    #define XFTELL(F)                f_tell((F))
    #define XREWIND(F)               f_rewind((F))
    #define XFREAD(BUF, SZ, AMT, F)  ({ FRESULT res; UINT br; res = f_read((F), (BUF), (SZ)*(AMT), &br); (void)br; res; })
    #define XFWRITE(BUF, SZ, AMT, F) ({ FRESULT res; UINT written; res = f_write((F), (BUF), (SZ)*(AMT), &written); (void)written; res; })
    #define XFCLOSE(F)               f_close((F))
    #define XSEEK_END                0
    #define XBADFILE                 NULL
    #define XFGETS(b,s,f)            f_gets((b), (s), (f))
#elif defined (_WIN32_WCE)
    /* stdio, WINCE case */
    #include <stdio.h>
    #define XFILE      FILE*
    #define XFOPEN     fopen
    #define XFDOPEN    fdopen
    #define XFSEEK     fseek
    #define XFTELL     ftell
    #define XREWIND(F) XFSEEK(F, 0, SEEK_SET)
    #define XFREAD     fread
    #define XFWRITE    fwrite
    #define XFCLOSE    fclose
    #define XSEEK_END  SEEK_END
    #define XBADFILE   NULL
    #define XFGETS     fgets
    #define XVSNPRINTF _vsnprintf

#elif defined(FUSION_RTOS)
    #include <fclstdio.h>
    #include <fclunistd.h>
    #include <fcldirent.h>
    #include <sys/fclstat.h>
    #include <fclstring.h>
    #include <fcl_os.h>
    #define XFILE     FCL_FILE*
    #define XFOPEN    FCL_FOPEN
    #define XFSEEK    FCL_FSEEK
    #define XFTELL    FCL_FTELL
    #define XREWIND   FCL_REWIND
    #define XFREAD    FCL_FREAD
    #define XFWRITE   FCL_FWRITE
    #define XFCLOSE   FCL_FCLOSE
    #define XSEEK_END SEEK_END
    #define XBADFILE  NULL
    #define XFGETS    FCL_FGETS
    #define XFPUTS    FCL_FPUTS
    #define XFPRINTF  FCL_FPRINTF
    #define XVFPRINTF FCL_VFPRINTF
    #define XVSNPRINTF  FCL_VSNPRINTF
    #define XSNPRINTF  FCL_SNPRINTF
    #define XSPRINTF  FCL_SPRINTF
    #define DIR       FCL_DIR
    #define stat      FCL_STAT
    #define opendir   FCL_OPENDIR
    #define closedir  FCL_CLOSEDIR
    #define readdir   FCL_READDIR
    #define dirent    fclDirent
    #define strncasecmp FCL_STRNCASECMP

    /* FUSION SPECIFIC ERROR CODE */
    #define FUSION_IO_SEND_E FCL_EWOULDBLOCK

#elif defined(WOLFSSL_USER_FILESYSTEM)
    /* To be defined in user_settings.h */
#else
    /* stdio, default case */
    #include <stdio.h>
    #define XFILE      FILE*
    #if defined(WOLFSSL_MDK_ARM)
        extern FILE * wolfSSL_fopen(const char *name, const char *mode) ;
        #define XFOPEN     wolfSSL_fopen
    #else
        #define XFOPEN     fopen
    #endif
    #define XFDOPEN    fdopen
    #define XFSEEK     fseek
    #define XFTELL     ftell
    #define XREWIND    rewind
    #define XFREAD     fread
    #define XFWRITE    fwrite
    #define XFCLOSE    fclose
    #define XSEEK_END  SEEK_END
    #define XBADFILE   NULL
    #define XFGETS     fgets
    #define XFPRINTF   fprintf
    #define XFFLUSH    fflush

    #if !defined(NO_WOLFSSL_DIR)\
        && !defined(WOLFSSL_NUCLEUS) && !defined(WOLFSSL_NUCLEUS_1_2)
    #if defined(USE_WINDOWS_API)
        #include <sys/stat.h>
        #define XSTAT       _stat
        #define XS_ISREG(s) (s & _S_IFREG)
        #define SEPARATOR_CHAR ';'

    #elif defined(INTIME_RTOS)
        #include <sys/stat.h>
        #define XSTAT _stat64
        #define XS_ISREG(s) S_ISREG(s)
        #define SEPARATOR_CHAR ';'
        #define XWRITE      write
        #define XREAD       read
        #define XCLOSE      close

    #elif defined(WOLFSSL_ZEPHYR)
        #define XSTAT       fs_stat
        #define XS_ISREG(s) (s == FS_DIR_ENTRY_FILE)
        #define SEPARATOR_CHAR ':'
    #elif defined(WOLFSSL_TELIT_M2MB)
        #define XSTAT       m2mb_fs_stat
        #define XS_ISREG(s) (s & M2MB_S_IFREG)
        #define SEPARATOR_CHAR ':'
    #else
        #include <dirent.h>
        #include <unistd.h>
        #include <sys/stat.h>
        #define XWRITE      write
        #define XREAD       read
        #define XCLOSE      close
        #define XSTAT       stat
        #define XS_ISREG(s) S_ISREG(s)
        #define SEPARATOR_CHAR ':'
    #endif

    #ifndef XSTAT_TYPE
        #define XSTAT_TYPE struct XSTAT
    #endif
    #endif
#endif

    #ifndef MAX_FILENAME_SZ
        #define MAX_FILENAME_SZ  256 /* max file name length */
    #endif
    #ifndef MAX_PATH
        #define MAX_PATH 256
    #endif

    WOLFSSL_LOCAL int wc_FileLoad(const char* fname, unsigned char** buf,
        size_t* bufLen, void* heap);

#if !defined(NO_WOLFSSL_DIR) && !defined(WOLFSSL_NUCLEUS) && \
    !defined(WOLFSSL_NUCLEUS_1_2)
    typedef struct ReadDirCtx {
    #ifdef USE_WINDOWS_API
        WIN32_FIND_DATAA FindFileData;
        HANDLE hFind;
        XSTAT_TYPE s;
    #elif defined(WOLFSSL_ZEPHYR)
        struct fs_dirent entry;
        struct fs_dir_t  dir;
        struct fs_dirent s;
        struct fs_dir_t* dirp;

    #elif defined(WOLFSSL_TELIT_M2MB)
        M2MB_DIR_T* dir;
        struct M2MB_DIRENT* entry;
        struct M2MB_STAT s;
    #elif defined(INTIME_RTOS)
        struct stat64 s;
        struct _find64 FindFileData;
        #define IntimeFindFirst(name, data) (0 == _findfirst64(name, data))
        #define IntimeFindNext(data)  (0 == _findnext64(data))
        #define IntimeFindClose(data) (0 == _findclose64(data))
        #define IntimeFilename(ctx)   ctx->FindFileData.f_filename
    #else
        struct dirent* entry;
        DIR*   dir;
        XSTAT_TYPE s;
    #endif
        char name[MAX_FILENAME_SZ];
    } ReadDirCtx;

    #define WC_READDIR_NOFILE (-1)

    WOLFSSL_API int wc_ReadDirFirst(ReadDirCtx* ctx, const char* path, char** name);
    WOLFSSL_API int wc_ReadDirNext(ReadDirCtx* ctx, const char* path, char** name);
    WOLFSSL_API void wc_ReadDirClose(ReadDirCtx* ctx);
#endif /* !NO_WOLFSSL_DIR */
    #define WC_ISFILEEXIST_NOFILE (-1)

    WOLFSSL_API int wc_FileExists(const char* fname);

#endif /* !NO_FILESYSTEM */

/* Defaults, user may over-ride with user_settings.h or in a porting section
 * above
 */
#ifndef XVFPRINTF
    #define XVFPRINTF  vfprintf
#endif
#ifndef XVSNPRINTF
    #define XVSNPRINTF vsnprintf
#endif
#ifndef XFPUTS
    #define XFPUTS     fputs
#endif
#ifndef XSPRINTF
    #define XSPRINTF   sprintf
#endif


/* MIN/MAX MACRO SECTION */
/* Windows API defines its own min() macro. */
#if defined(USE_WINDOWS_API)
    #if defined(min) || defined(WOLFSSL_MYSQL_COMPATIBLE)
        #define WOLFSSL_HAVE_MIN
    #endif /* min */
    #if defined(max) || defined(WOLFSSL_MYSQL_COMPATIBLE)
        #define WOLFSSL_HAVE_MAX
    #endif /* max */
#endif /* USE_WINDOWS_API */

#ifdef __QNXNTO__
    #define WOLFSSL_HAVE_MIN
    #define WOLFSSL_HAVE_MAX
#endif

/* TIME SECTION */
/* Time functions */
#ifndef NO_ASN_TIME
#if defined(USER_TIME)
    /* Use our gmtime and time_t/struct tm types.
       Only needs seconds since EPOCH using XTIME function.
       time_t XTIME(time_t * timer) {}
    */
    #define WOLFSSL_GMTIME
    #ifndef HAVE_TM_TYPE
        #define USE_WOLF_TM
    #endif
    #ifndef HAVE_TIME_T_TYPE
        #define USE_WOLF_TIME_T
    #endif

#elif defined(TIME_OVERRIDES)
    /* Override XTIME() and XGMTIME() functionality.
       Requires user to provide these functions:
        time_t XTIME(time_t * timer) {}
        struct tm* XGMTIME(const time_t* timer, struct tm* tmp) {}
    */
    #ifndef HAVE_TIME_T_TYPE
        #define USE_WOLF_TIME_T
    #endif
    #ifndef HAVE_TM_TYPE
        #define USE_WOLF_TM
    #endif
    #define NEED_TMP_TIME

#elif defined(WOLFSSL_XILINX)
    #ifndef XTIME
        #define XTIME(t1)       xilinx_time((t1))
    #endif
    #include <time.h>

#elif defined(HAVE_RTP_SYS)
    #include "os.h"           /* dc_rtc_api needs    */
    #include "dc_rtc_api.h"   /* to get current time */

    /* uses parital <time.h> structures */
    #define XTIME(tl)       (0)
    #define XGMTIME(c, t)   rtpsys_gmtime((c))

#elif defined(WOLFSSL_DEOS)
    #include <time.h>

#elif defined(MICRIUM)
    #include <clk.h>
    #include <time.h>
    #define XTIME(t1)       micrium_time((t1))
    #define WOLFSSL_GMTIME

#elif defined(MICROCHIP_TCPIP_V5) || defined(MICROCHIP_TCPIP)
    #include <time.h>
    extern time_t pic32_time(time_t* timer);
    #define XTIME(t1)       pic32_time((t1))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    #ifdef FREESCALE_MQX_4_0
        #include <time.h>
        extern time_t mqx_time(time_t* timer);
    #else
        #define HAVE_GMTIME_R
    #endif
    #define XTIME(t1)       mqx_time((t1))

#elif defined(FREESCALE_KSDK_BM) || defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)
    #include <time.h>
    #ifndef XTIME
        /*extern time_t ksdk_time(time_t* timer);*/
        #define XTIME(t1)   ksdk_time((t1))
    #endif
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(WOLFSSL_ATMEL) && defined(WOLFSSL_ATMEL_TIME)
    #define XTIME(t1)       atmel_get_curr_time_and_date((t1))
    #define WOLFSSL_GMTIME
    #define USE_WOLF_TM
    #define USE_WOLF_TIME_T

#elif defined(WOLFSSL_WICED)
    #include <time.h>
    time_t wiced_pseudo_unix_epoch_time(time_t * timer);
    #define XTIME(t1)       wiced_pseudo_unix_epoch_time((t1))
    #define HAVE_GMTIME_R

#elif defined(IDIRECT_DEV_TIME)
    /*Gets the timestamp from cloak software owned by VT iDirect
    in place of time() from <time.h> */
    #include <time.h>
    #define XTIME(t1)       idirect_time((t1))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(_WIN32_WCE)
    #include <windows.h>
    #include <stdlib.h> /* For file system */

    time_t windows_time(time_t* timer);

    #define FindNextFileA(h, d) FindNextFile(h, (LPWIN32_FIND_DATAW) d)
    #define FindFirstFileA(fn, d) FindFirstFile((LPCWSTR) fn, \
                                                (LPWIN32_FIND_DATAW) d)
    #define XTIME(t1)       windows_time((t1))
    #define WOLFSSL_GMTIME

    /* if struct tm is not defined in WINCE SDK */
    #ifndef _TM_DEFINED
        struct tm {
            int tm_sec;     /* seconds */
            int tm_min;     /* minutes */
            int tm_hour;    /* hours */
            int tm_mday;    /* day of month (month specific) */
            int tm_mon;     /* month */
            int tm_year;    /* year */
            int tm_wday;    /* day of week (out of 1-7)*/
            int tm_yday;    /* day of year (out of 365) */
            int tm_isdst;   /* is it daylight savings */
            };
            #define _TM_DEFINED
    #endif

#elif defined(WOLFSSL_APACHE_MYNEWT)
    #include "os/os_time.h"
    #define XTIME(t1)       mynewt_time((t1))
    #define WOLFSSL_GMTIME
    #define USE_WOLF_TM
    #define USE_WOLF_TIME_T

#elif defined(WOLFSSL_ZEPHYR)
    #ifndef _POSIX_C_SOURCE
        #include <posix/time.h>
    #else
        #include <sys/time.h>
    #endif

    time_t z_time(time_t *timer);

    #define XTIME(tl)       z_time((tl))
    #define XGMTIME(c, t)   gmtime((c))

#elif defined(WOLFSSL_TELIT_M2MB)
    typedef long time_t;
    extern time_t m2mb_xtime(time_t * timer);
    #define XTIME(tl)       m2mb_xtime((tl))
    #ifdef WOLFSSL_TLS13
        extern time_t m2mb_xtime_ms(time_t * timer);
        #define XTIME_MS(tl)    m2mb_xtime_ms((tl))
    #endif
    #ifndef NO_CRYPT_BENCHMARK
        extern double m2mb_xtime_bench(int reset);
        #define WOLFSSL_CURRTIME_REMAP m2mb_xtime_bench
    #endif
    #define XGMTIME(c, t)   gmtime((c))
    #define WOLFSSL_GMTIME
    #define USE_WOLF_TM


#elif defined(WOLFSSL_LINUXKM)

    /* definitions are in linuxkm/linuxkm_wc_port.h */

#elif defined(HAL_RTC_MODULE_ENABLED)
    #include <time.h>
    WOLFSSL_LOCAL time_t* stm32_hal_time(time_t* t1);
    #define XTIME(t1) stm32_hal_time(t1)
    #define WOLFSSL_GMTIME
#else
    /* default */
    /* uses complete <time.h> facility */
    #include <time.h>
    #if defined(HAVE_SYS_TIME_H)
        #include <sys/time.h>
    #endif

    /* PowerPC time_t is int */
    #ifdef __PPC__
        #define TIME_T_NOT_64BIT
    #endif

    #define XMKTIME(tm) mktime(tm)
    #define XDIFFTIME(to, from) difftime(to, from)
#endif

#ifdef SIZEOF_TIME_T
    /* check if size of time_t from autoconf is less than 8 bytes (64bits) */
    #if SIZEOF_TIME_T < 8
        #undef  TIME_T_NOT_64BIT
        #define TIME_T_NOT_64BIT
    #endif
#endif
#ifdef TIME_T_NOT_LONG
    /* one old reference to TIME_T_NOT_LONG in GCC-ARM example README
     * this keeps support for the old macro name */
    #undef  TIME_T_NOT_64BIT
    #define TIME_T_NOT_64BIT
#endif

/* Map default time functions */
#if !defined(XTIME) && !defined(TIME_OVERRIDES) && !defined(USER_TIME)
    #ifdef TEST_BEFORE_DATE
    #define XTIME(tl)       (946681200UL) /* Jan 1, 2000 */
    #else
    #define XTIME(tl)       time((tl))
    #endif
#endif
#if !defined(XGMTIME) && !defined(TIME_OVERRIDES)
    /* Always use gmtime_r if available. */
    #if defined(HAVE_GMTIME_S)
        /* reentrant version */
        #define XGMTIME(c, t)   gmtime_s((c), (t))
        #define NEED_TMP_TIME
    #elif defined(HAVE_GMTIME_R)
        #define XGMTIME(c, t)   gmtime_r((c), (t))
        #define NEED_TMP_TIME
    #else
        #define XGMTIME(c, t)   gmtime((c))
    #endif
#endif
#if !defined(XVALIDATE_DATE) && !defined(HAVE_VALIDATE_DATE)
    #define USE_WOLF_VALIDDATE
    #define XVALIDATE_DATE(d, f, t) wc_ValidateDate((d), (f), (t))
#endif

/* wolf struct tm and time_t */
#if defined(USE_WOLF_TM)
    struct tm {
        int  tm_sec;     /* seconds after the minute [0-60] */
        int  tm_min;     /* minutes after the hour [0-59] */
        int  tm_hour;    /* hours since midnight [0-23] */
        int  tm_mday;    /* day of the month [1-31] */
        int  tm_mon;     /* months since January [0-11] */
        int  tm_year;    /* years since 1900 */
        int  tm_wday;    /* days since Sunday [0-6] */
        int  tm_yday;    /* days since January 1 [0-365] */
        int  tm_isdst;   /* Daylight Savings Time flag */
        long tm_gmtoff;  /* offset from CUT in seconds */
        char *tm_zone;   /* timezone abbreviation */
    };
#endif /* USE_WOLF_TM */
#if defined(USE_WOLF_TIME_T)
    typedef long time_t;
#endif
#if defined(USE_WOLF_SUSECONDS_T)
    typedef long suseconds_t;
#endif
#if defined(USE_WOLF_TIMEVAL_T)
    struct timeval
    {
        time_t tv_sec;
        suseconds_t tv_usec;
    };
#endif

    /* forward declarations */
#if defined(USER_TIME)
    struct tm* gmtime(const time_t* timer);
    extern time_t XTIME(time_t * timer);

    #ifdef STACK_TRAP
        /* for stack trap tracking, don't call os gmtime on OS X/linux,
           uses a lot of stack spce */
        extern time_t time(time_t * timer);
        #define XTIME(tl)  time((tl))
    #endif /* STACK_TRAP */

#elif defined(TIME_OVERRIDES)
    extern time_t XTIME(time_t * timer);
    extern struct tm* XGMTIME(const time_t* timer, struct tm* tmp);
#elif defined(WOLFSSL_GMTIME)
    struct tm* gmtime(const time_t* timer);
#endif
#endif /* NO_ASN_TIME */


#ifndef WOLFSSL_LEANPSK
    char* mystrnstr(const char* s1, const char* s2, unsigned int n);
#endif

#ifndef FILE_BUFFER_SIZE
    /* default static file buffer size for input, will use dynamic buffer if
     * not big enough */
    #ifdef WOLFSSL_CERT_EXT
    #define FILE_BUFFER_SIZE (3*1024)
    #else
    #define FILE_BUFFER_SIZE (1*1024)
    #endif
#endif

#ifdef HAVE_CAVIUM_OCTEON_SYNC
    /* By default, the OCTEON's global variables are all thread local. This
     * tag allows them to be shared between threads. */
    #include "cvmx-platform.h"
    #define WOLFSSL_GLOBAL CVMX_SHARED
#else
    #define WOLFSSL_GLOBAL
#endif

#ifdef WOLFSSL_DSP
    #include "wolfssl_dsp.h"

    /* callbacks for setting handle */
    typedef int (*wolfSSL_DSP_Handle_cb)(remote_handle64 *handle, int finished,
                                         void *ctx);
    WOLFSSL_API int wolfSSL_GetHandleCbSet();
    WOLFSSL_API int wolfSSL_SetHandleCb(wolfSSL_DSP_Handle_cb in);
    WOLFSSL_LOCAL int wolfSSL_InitHandle();
    WOLFSSL_LOCAL void wolfSSL_CleanupHandle();
#endif

#ifdef WOLFSSL_SCE
    #ifndef WOLFSSL_SCE_GSCE_HANDLE
        #define WOLFSSL_SCE_GSCE_HANDLE g_sce
    #endif
#endif

#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLF_CRYPT_PORT_H */
