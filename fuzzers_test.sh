#!/bin/sh

# runs fuzz corpus with standalone fuzzers

result=0

test -d fuzzcorpus && hg --repository fuzzcorpus/ pull || hg clone https://hg.ucc.asn.au/dropbear-fuzzcorpus fuzzcorpus || exit 1
for f in `make list-fuzz-targets`; do
    # use xargs to split the too-long argument list
    echo fuzzcorpus/$f/* | xargs -n 1000 ./$f || result=1
done

exit $result
