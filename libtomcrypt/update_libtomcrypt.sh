#!/bin/tcsh
# Get latest copy of libtomcrypt and install it using "tcsh"
#
# Tom St Denis
echo libtomcrypt update script, Tom St Denis
echo "http://libtomcrypt.iahu.ca\n"

if ($1 == "--help") then
   echo "update_libtomcrypt.sh [makefile] [sig]-- Download and optionally build the libtomcrypt project.\n"
   echo "\t[makefile] --\tYou can optionally specify which makefile you want to build with. If you specify "
   echo "\t\t\t'nobuild' then the library is not built, just downloaded and unzipped.  If you "
   echo "\t\t\tleave it empty the default 'makefile' is used to build the library.\n"
   echo "\t[sig] -- \tOptionally verify [via GPG] the signature of the package."
   exit
endif

if ($1 == "" || $1 == "sig") then
   set make = "makefile"
else
   set make = $1;
endif

if ($1 == "sig" || $2 == "sig") then
   set sig = "sig"
else
   set sig = ""
endif   

rm -f latest
echo Getting latest version number from website.
wget -q http://iahu.ca:8080/download/latest
if (-r latest) then 
   set a = `cat latest`
   echo "Latest release is v$a.\n"
   if (-d "libtomcrypt-$a" && (-r "libtomcrypt-$a/libtomcrypt.a" || $make == "nobuild")) then
      echo Libtomcrypt v$a is already installed on your system.
   else   
      echo "Downloading libtomcrypt v$a ..."
      if (-r "crypt-$a.tar.bz2") then 
         rm -f crypt-$a.tar.bz2
      endif
      wget http://iahu.ca:8080/download/crypt-$a.tar.bz2
      if (-r "crypt-$a.tar.bz2") then 
         if (-d "libtomcrypt-$a") then
            echo "WARNING!  Directory libtomcrypt-$a already exists.  Cannot continue.\n"
            exit            
         endif
         if ($sig == "sig") then
            if (!(-r public.asc)) then
               echo "Downloading and installing code signing key...\n"
               wget -q http://iahu.ca:8080/download/public.asc
               if (-r public.asc) then 
                  gpg --import public.asc
                  if ($? != 0) then
                     echo Could not import signing key required to verify the package.
                     exit
                  else
                     echo "\n********************************************************************************"
                     echo "A new key has been imported to your keyring.  You should check that it is valid."
                     echo "********************************************************************************"
                  endif
               else 
                  echo "Could not download the key to import."
                  exit
               endif
            endif
            echo Verifying signature...
            wget -q http://iahu.ca:8080/download/crypt-$a.tar.bz2.asc
            if (!(-r "crypt-$a.tar.bz2.asc")) then
               echo Could not download signature to test.
               exit
            endif
            gpg -q --verify crypt-$a.tar.bz2.asc
            if ($? != 0) then 
               echo "\n\nSignature for crypt-$a.tar.bz2 is ****not**** valid.\n\n"
               exit
            else
               echo "\n\nSignature for crypt-$a.tar.bz2 is valid.\n\n"
            endif
         endif
         bzip2 -d -c crypt-$a.tar.bz2 | tar -x 
         if (-d "libtomcrypt-$a") then
            if (-r "libtomcrypt-$a/$make") then 
               cd libtomcrypt-$a
               make -f $make
               if (-r "libtomcrypt.a") then
                  echo "\n\n*****************************************************************"
                  echo The library has been built and you can now install it either with
                  echo 
                  echo "cd libtomcrypt-$a ; make install"
                  echo
                  echo Or by editing the makefile and changing the user you wish to install 
                  echo it with, or simply copy "libtomcrypt.a" to your library directory and 
                  echo copy "*.h" to your include directory
                  echo "*****************************************************************"
               else 
                  echo "\n\n*****************************************************************"
                  echo The library failed to build.  Please note the errors and send them to tomstdenis@yahoo.com
                  echo "*****************************************************************"
               endif
            else if ($make == "nobuild") then
                  echo "\n\n*****************************************************************"
                  echo "The library was downloaded and unzipped into libtomcrypt-$a/"
                  echo "*****************************************************************"
            else
               echo "The makefile '$make' was not found in the archive.\n";
            endif
         else 
            echo "Could not unpack the libtomcrypt archive (corrupt?)."
         endif
         cd ..
      else
         echo "Could not download the libtomcrypt archive from server."
      endif
   endif
   if (-r "libtomcrypt-$a/changes") then
      perl <<!
      open(IN,"<libtomcrypt-$a/changes") or die "Can't open libtomcrypt change log.";
      print "\nChange log for v$a :\n";
      \$a = <IN>; print \$a; \$a = <IN>;
      while (<IN>) { 
         if (\$_ =~ m/^(v\d\.\d\d)/) { close(IN); exit(0); } 
         print "\$a"; \$a = \$_; 
      }
!
   else 
      echo "Change log not found.  Is the package really installed?"
   endif
else 
   echo "Could not download latest file from server to check version."
endif
