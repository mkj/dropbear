#!/bin/bash
bash build.sh " $1" "$2 -O2" "$3 IGNORE_SPEED=1"
if [ -a testok.txt ] && [ -f testok.txt ]; then
   echo
else
	echo
	echo "Test failed"
	exit 1
fi

rm -f testok.txt
bash build.sh " $1" "$2 -Os" " $3 IGNORE_SPEED=1 LTC_SMALL=1"
if [ -a testok.txt ] && [ -f testok.txt ]; then
   echo
else
	echo
	echo "Test failed"
	exit 1
fi

rm -f testok.txt
bash build.sh " $1" " $2" " $3"
if [ -a testok.txt ] && [ -f testok.txt ]; then
   echo
else
	echo
	echo "Test failed"
	exit 1
fi

exit 0

# $Source: /cvs/libtom/libtomcrypt/run.sh,v $   
# $Revision: 1.13 $   
# $Date: 2005/05/11 18:59:53 $ 
