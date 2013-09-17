#!/bin/sh
cc -fPIC -c pam_unshare.c
gcc -shared -o pam_unshare.so pam_unshare.o -lpam
cp pam_unshare.so /lib/security
