#!/bin/bash

# date
echo "date="`date`

# output version
echo "Testing verion" `grep "^VERSION=" makefile | sed "s/.*=//"`
#grep "VERSION=" makefile | perl -e "@a = split('=', <>); print @a[1];"`

# get uname 
echo "uname="`uname -a`
echo

# stock build
bash run.sh "STOCK" " " $1 || exit 1

# SMALL code
bash run.sh "SMALL" "-DLTC_SMALL_CODE" $1 || exit 1

# NOTABLES
bash run.sh "NOTABLES" "-DLTC_NO_TABLES" $1 || exit 1

# SMALL+NOTABLES
bash run.sh "SMALL+NOTABLES" "-DLTC_SMALL_CODE -DLTC_NO_TABLES" $1 || exit 1

# CLEANSTACK
bash run.sh "CLEANSTACK" "-DLTC_CLEAN_STACK" $1 || exit 1

# CLEANSTACK + SMALL
bash run.sh "CLEANSTACK+SMALL" "-DLTC_SMALL_CODE -DLTC_CLEAN_STACK" $1 || exit 1

# CLEANSTACK + NOTABLES
bash run.sh "CLEANSTACK+NOTABLES" "-DLTC_NO_TABLES -DLTC_CLEAN_STACK" $1 || exit 1

# CLEANSTACK + NOTABLES + SMALL
bash run.sh "CLEANSTACK+NOTABLES+SMALL" "-DLTC_NO_TABLES -DLTC_CLEAN_STACK -DLTC_SMALL_CODE" $1 || exit 1

# NO_FAST
bash run.sh "NO_FAST" "-DLTC_NO_FAST" $1 || exit 1

# NO_ASM
bash run.sh "NO_ASM" "-DLTC_NO_ASM" $1 || exit 1

# test build with no testing
bash testbuild.sh "NOTEST" "-DLTC_NO_TEST" $1 || exit 1

# test build with no file routines
bash testbuild.sh "NOFILE" "-DLTC_NO_FILE" $1 || exit 1

# $Source: /cvs/libtom/libtomcrypt/testme.sh,v $   
# $Revision: 1.16 $   
# $Date: 2005/05/11 18:59:53 $ 
