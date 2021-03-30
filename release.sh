#!/bin/sh

set -e

VERSION=$(echo '#include "sysoptions.h"\necho DROPBEAR_VERSION' | cpp - | sh)
echo Releasing version "$VERSION" ...
if ! head -n1 CHANGES | grep -q $VERSION ; then
	echo "CHANGES needs updating"
	exit 1
fi

if ! head -n1 debian/changelog | grep -q $VERSION ; then
	echo "debian/changelog needs updating"
	exit 1
fi

head -n1 CHANGES

if tar --version | grep -q 'GNU tar'; then
	TAR=tar
else
	TAR=gtar
fi

RELDIR=$PWD/../dropbear-$VERSION
ARCHIVE=${RELDIR}.tar.bz2
if test -e $RELDIR; then
	echo "$RELDIR exists"
	exit 1
fi

if test -e $ARCHIVE; then
	echo "$ARCHIVE exists"
	exit 1
fi

hg archive "$RELDIR"  || exit 2

(cd "$RELDIR" && autoconf && autoheader) || exit 2

rm -r "$RELDIR/autom4te.cache" || exit 2

rm "$RELDIR/.hgtags"

RELDATE=$(head -n1 CHANGES | cut -d - -f 2)

# from https://reproducible-builds.org/docs/archives/
TAROPTS="--sort=name --owner=0 --group=0 --numeric-owner"
(cd "$RELDIR/.." && $TAR cjf $ARCHIVE $TAROPTS --mtime="$RELDATE" `basename "$RELDIR"`) || exit 2

ls -l $ARCHIVE
openssl sha256 $ARCHIVE
echo Done to
echo "$ARCHIVE"
echo Sign it with
echo gpg2 --detach-sign -a -u F29C6773 "$ARCHIVE"
