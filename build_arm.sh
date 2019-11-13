cd ./third_party/openssl
make clean
./Configure linux-armv4 shared -DL_ENDIAN --prefix=/usr/local/ #--openssldir=./
make CC=arm-linux-gnueabi-gcc RANLIB=arm-linux-gnueabi-ranlib LD=arm-linux-gnueabi-ld MAKEDEPPROG=arm-linux-gnueabi-gcc PROCESSOR=ARM -j4
make install -j4