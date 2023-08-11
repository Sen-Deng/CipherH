#!/bin/bash
set -e
set -x
set -u

# setup llvm env variables
cd ../..
. ./setup.sh
cd - > /dev/null

DIR=`pwd`
cd ../../passes
make install || exit 1
cd ../lib
make install || exit 2
cd $DIR

file="test.c"
cc="clang"
PROJECT_NAME=${file%.*}

OPT=${OPT:-2}

# we take optimizations from O1, but we exclude -loop-unroll, -jump-threading, -pgo-memop-opt and -loop-unswitch as they usually create more complex CFGs
# moreover use a custom loop-idiom to disable memcpy recognition
SAFE_OPTS='-tti -tbaa -scoped-noalias -assumption-cache-tracker -targetlibinfo -verify -ee-instrument -simplifycfg -domtree -sroa -early-cse -lower-expect -tti -tbaa -scoped-noalias -assumption-cache-tracker -profile-summary-info -forceattrs -inferattrs -ipsccp -called-value-propagation -attributor -globalopt -domtree -mem2reg -deadargelim -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -simplifycfg -basiccg -globals-aa -prune-eh -always-inline -functionattrs -domtree -sroa -basicaa -aa -memoryssa -early-cse-memssa -speculative-execution -basicaa -aa -lazy-value-info -correlated-propagation -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -libcalls-shrinkwrap -loops -branch-prob -block-freq -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -tailcallelim -simplifycfg -reassociate -domtree -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -loop-rotate -licm -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -indvars -custom-loop-idiom -disable-custom-loop-idiom-memcpy -loop-deletion -phi-values -memdep -memcpyopt -sccp -demanded-bits -bdce -basicaa -aa -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -lazy-value-info -correlated-propagation -basicaa -aa -phi-values -memdep -dse -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -licm -postdomtree -adce -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -barrier -basiccg -rpo-functionattrs -globalopt -globaldce -basiccg -globals-aa -float2int -domtree -loops -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -loop-rotate -loop-accesses -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -loop-distribute -branch-prob -block-freq -scalar-evolution -basicaa -aa -loop-accesses -demanded-bits -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -loop-simplify -scalar-evolution -aa -loop-accesses -lazy-branch-prob -lazy-block-freq -loop-load-elim -basicaa -aa -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -simplifycfg -domtree -basicaa -aa -loops -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instcombine -loop-simplify -lcssa-verification -lcssa -scalar-evolution -licm -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -transform-warning -alignment-from-assumptions -strip-dead-prototypes -domtree -loops -branch-prob -block-freq -loop-simplify -lcssa-verification -lcssa -basicaa -aa -scalar-evolution -block-freq -lazy-branch-prob -lazy-block-freq -opt-remark-emitter -instsimplify -div-rem-pairs -simplifycfg -targetlibinfo -domtree -loops -branch-prob -block-freq'

if [ $OPT -eq 0 ]; then
CFLAGS="-g -Og -mllvm -x86-cmov-converter=0 "
OFLAGS="-O0"
LDFLAGS="-Og"
else
CFLAGS="-O$OPT -fno-unroll-loops -mllvm -x86-cmov-converter=0 -g"
OFLAGS="-O$OPT --disable-loop-unrolling"
LDFLAGS="-O$OPT "
fi

DFSAN_ABILIST=`$cc -fsanitize=dataflow -c $file -### 2>&1 | grep sanitize | sed "s/.*-fsanitize-blacklist=\([^\"]*\).*/\1/g"`

cat $DFSAN_ABILIST ../../lib/dft/dfsan.abilist > dfsan_abilist.txt


clang  -O1 -fno-delete-null-pointer-checks -fno-unroll-loops -flto -c -o $PROJECT_NAME.base.bc $file -fno-exceptions

llvm-link -o $PROJECT_NAME.linked.bc $PROJECT_NAME.base.bc wolfssl.bc


../opt -coverage-id -coverage-id-b-gids -coverage-id-i-bids -check-undefined -o $PROJECT_NAME.coverage-id.bc $PROJECT_NAME.linked.bc

llvm-link -o $PROJECT_NAME.dft.bc $PROJECT_NAME.coverage-id.bc ../../bin/dft.bcc

../opt -taintglb -taintglb-vars='^key$' -check-undefined -o $PROJECT_NAME.taintglb.bc $PROJECT_NAME.dft.bc

../opt -scalarizer -scalarize-load-store -lowerinvoke -hook -hook-inline -hook-base-args-tls=0 -hook-base-args=b-gid,i-bid -check-undefined -o $PROJECT_NAME.hook.bc $PROJECT_NAME.taintglb.bc

../opt -dfsan -dfsan-abilist=dfsan_abilist.txt -fix-callsite-attrs $OFLAGS -check-undefined -o $PROJECT_NAME.final.bc $PROJECT_NAME.hook.bc

$cc  $CFLAGS -fPIC -DPIC -o $PROJECT_NAME.final.o -c $PROJECT_NAME.final.bc
$cc  $LDFLAGS -fno-exceptions -fsanitize=dataflow -o $PROJECT_NAME.dft.out  -ldl -lm -pthread $PROJECT_NAME.final.o ../../lib/dft/dft.o

rm dft.log || true

