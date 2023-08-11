#include <dft.h>

/* Use this function to inject initialization steps */
void __attribute__((used)) __attribute__((noinline)) dft_pass_init(dfsan_label label) {
    //asm volatile ("");
    return;
}

void __attribute__((used)) wrap_dft_set_label(dfsan_label label, void* addr, size_t size) {
    dfsan_set_label(label, addr, size);
    return;
}

/* Need to wrap main to initialize. */
extern int __dft_main(int argc, char** argv);

int __hook_wrap_call___main(DFT_ARG_PREFIX int argc, char** argv)
{
    return __dft_main(argc, argv);
}

#ifdef DFT_WRAP_SOURCES
extern ssize_t __dft_read(void *buf, ssize_t size);

ssize_t __hook_wrap_call_read(DFT_ARG_PREFIX int fd, void *buf, size_t count)
{
	ssize_t size = read(fd, buf, count);
	return __dft_read(buf, size);
}

ssize_t __hook_wrap_call_pread(DFT_ARG_PREFIX int fd, void *buf, size_t count, off_t offset)
{
	ssize_t size = pread(fd, buf, count, offset);
	return __dft_read(buf, size);
}

size_t __hook_wrap_call_fread(DFT_ARG_PREFIX void *buf, size_t count, size_t n, FILE *stream)
{
	ssize_t size = fread(buf, count, n, stream);
	return (size_t) __dft_read(buf, size);
}
#endif

#ifndef DFT_SKIP_CMP
extern void __dft_cmp(DFT_ARG_PREFIX bool cmp);
extern void __dft_switch(DFT_ARG_PREFIX unsigned long long value);
extern void __dft_br(DFT_ARG_PREFIX bool taken);

void __hook_post_icmp(DFT_ARG_PREFIX bool cmp)
{   
    __dft_cmp(DFT_VAL_PREFIX cmp);
}

void __hook_post_fcmp(DFT_ARG_PREFIX bool cmp)
{
    __dft_cmp(DFT_VAL_PREFIX cmp);
}

void __hook_post_switch(DFT_ARG_PREFIX unsigned long long value)
{
    __dft_switch(DFT_VAL_PREFIX value);
}

void __hook_post_br(DFT_ARG_PREFIX bool taken)
{
    __dft_br(DFT_VAL_PREFIX taken);
}
#endif

#ifndef DFT_SKIP_ICALL
extern void __dft_icall(DFT_ARG_PREFIX void *fptr);

void __hook_post_icall(DFT_ARG_PREFIX void *fptr)
{
    __dft_icall(DFT_VAL_PREFIX fptr);
}
#endif

void __hook_post_load(imd_t ID1, imd_t *ID2, char* value1)
{
     printf("%s:", value1);
}  

void __hook_pre_load(imd_t ID1, imd_t *ID2, long* ptr)
{   
    long a = *ptr;
    dfsan_label value_label = dfsan_get_label(a);
    int c = 0;
    printf("%d", c);
    printf("%d",c);
    printf("%d", c);
    printf("%d", c);
    printf("%d", c);
    printf("%d", c); 
    printf("%d", c);
    printf("%d\n", value_label); 
}

void __hook_pre_call(imd_t ID1, imd_t *ID2, char* value1)
{
    printf("%s:", value1);
}   

void __hook_post_call(imd_t ID1, imd_t *ID2, long value1, long value2, long value3, long value4, long value5, long value6)
{   
    dfsan_label value1_label = dfsan_get_label(value1);
    dfsan_label value2_label = dfsan_get_label(value2);
    dfsan_label value3_label = dfsan_get_label(value3);
    dfsan_label value4_label = dfsan_get_label(value4);
    dfsan_label value5_label = dfsan_get_label(value5);
    dfsan_label value6_label = dfsan_get_label(value6);   
    int c = 0;
    printf("%d", value1_label);
    printf("%d", value2_label);
    printf("%d", value3_label);
    printf("%d", value4_label);
    printf("%d", value5_label);
    printf("%d", value6_label); 
    printf("%d", c);
    printf("%d\n", c); 
}   

void __hook_post_ret(imd_t ID1, imd_t *ID2, char* value1)
{printf("%s:", value1);
    
}  

void __hook_pre_ret(imd_t ID1, imd_t *ID2, long a)
{     
     dfsan_label value_label = dfsan_get_label(a);
     int c = 0;
    printf("%d", c);
    printf("%d",c);
    printf("%d", c);
    printf("%d", c);
    printf("%d", c);
    printf("%d", c); 
    printf("%d", value_label);
    printf("%d\n", c); 

}

#ifndef DFT_SKIP_GEP
extern void __dft_getelementptr(DFT_ARG_PREFIX void *gep, void *ptr);

void __hook_post_getelementptr(DFT_ARG_PREFIX void *gep, void *ptr)
{
    __dft_getelementptr(DFT_VAL_PREFIX gep, ptr);
}
#endif

#ifndef DFT_SKIP_MEM
extern void __dft_load(DFT_ARG_PREFIX void *ptr);
extern void __dft_store(DFT_ARG_PREFIX long long value, void *ptr);
extern void __dft_memcpy(DFT_ARG_PREFIX void *dst, void *src, size_t len);
extern void __dft_memmove(DFT_ARG_PREFIX void *dst, void *src, size_t len);
extern void __dft_memset(DFT_ARG_PREFIX void *dst, char val, size_t len);



void __hook_post_store(DFT_ARG_PREFIX long long value, void *ptr)
{
    __dft_store(DFT_VAL_PREFIX value, ptr);
}

void __hook_post_llvm_memcpy(DFT_ARG_PREFIX void *dst, void *src, size_t len)
{
    __dft_memcpy(DFT_VAL_PREFIX dst, src, len);
}

void __hook_post_llvm_memcpy_element_unordered_atomic(DFT_ARG_PREFIX void *dst, void *src, size_t len)
{
    __dft_memcpy(DFT_VAL_PREFIX dst, src, len);
}

void __hook_post_llvm_memmove(DFT_ARG_PREFIX void *dst, void *src, size_t len)
{
    __dft_memmove(DFT_VAL_PREFIX dst, src, len);
}

void __hook_post_llvm_memmove_element_unordered_atomic(DFT_ARG_PREFIX void *dst, void *src, size_t len)
{
    __dft_memmove(DFT_VAL_PREFIX dst, src, len);
}

void __hook_post_llvm_memset(DFT_ARG_PREFIX void *dst, char val, size_t len)
{
    __dft_memset(DFT_VAL_PREFIX dst, val, len);
}

void __hook_post_llvm_memset_element_unordered_atomic(DFT_ARG_PREFIX void *dst, char val, size_t len)
{
    __dft_memset(DFT_VAL_PREFIX dst, val, len);
}
#endif

#ifndef DFT_SKIP_DIV
extern void __dft_div(DFT_ARG_PREFIX signed long long value);
extern void __dft_rem(DFT_ARG_PREFIX signed long long value);

void __hook_post_udiv(DFT_ARG_PREFIX unsigned long long value)
{
    __dft_div(DFT_VAL_PREFIX (signed long long) value);
}
void __hook_post_sdiv(DFT_ARG_PREFIX signed long long value)
{
    __dft_div(DFT_VAL_PREFIX value);
}
void __hook_post_fdiv(DFT_ARG_PREFIX long double value)
{
    __dft_div(DFT_VAL_PREFIX (signed long long) value);
}
void __hook_post_urem(DFT_ARG_PREFIX unsigned long long value)
{
    __dft_rem(DFT_VAL_PREFIX (signed long long) value);
}
void __hook_post_srem(DFT_ARG_PREFIX signed long long value)
{
    __dft_rem(DFT_VAL_PREFIX value);
}
#endif






