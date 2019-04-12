#!/bin/bash

./helper.pl --update-makefiles || exit 1

makefiles=(makefile makefile.shared makefile_include.mk makefile.msvc makefile.unix makefile.mingw)
vcproj=(libtommath_VS2008.vcproj)

if [ $# -eq 1 ] && [ "$1" == "-c" ]; then
  git add ${makefiles[@]} ${vcproj[@]} && git commit -m 'Update makefiles'
fi

exit 0

# ref:         HEAD -> master, tag: v1.1.0
# git commit:  08549ad6bc8b0cede0b357a9c341c5c6473a9c55
# commit time: 2019-01-28 20:32:32 +0100
