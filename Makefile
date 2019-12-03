ifeq ($(ARM), y)
CROSS = arm-linux-gnueabi-
CC = $(CROSS)gcc
CXX = $(CROSS)g++
AR = $(CROSS)ar
RANLIB = $(CROSS)ranlib
LD = $(CROSS)ld
STRIP = $(CROSS)strip
export CC CXX AR RANLIB
endif

ROOT_DIR = $(CURDIR)
MBEDTLS = $(ROOT_DIR)/mbedtls

CFLAGS = -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -O2 -g3
LDFLAGS =

INCLUDES = -I$(MBEDTLS)/include -I$(ROOT_DIR)/third_party/openssl/include
LIBS = $(MBEDTLS)/library/libmbedx509.a $(MBEDTLS)/library/libmbedtls.a $(MBEDTLS)/library/libmbedcrypto.a

SOURCES = main.c https.c crypto_utils.c serializer.c tryte_byte_conv.c uart_utils.c

OBJS = $(SOURCES:.c=.o)

.SUFFIXES:.c .o

all: ta_client

mbedtls_make:
	@for dir in $(MBEDTLS); do \
		$(MAKE) -C $$dir ; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done

ta_client: mbedtls_make $(OBJS)
	@echo Linking: $@ ....
	$(CC) -g -o $@ $(OBJS) $(LDFLAGS) $(LIBS) -L$(ROOT_DIR)/third_party/openssl -lcrypto

%.o: %.c
	@echo Compiling: $< ....
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $^

test: 
	$(CC) -g -o test_tryte_byte_conv test_tryte_byte_conv.c tryte_byte_conv.c
	$(CC) -g -o test_crypto_utils test_crypto_utils.c crypto_utils.c -lcrypto
	$(CC) -g -o test_serializer test_serializer.c serializer.c

clean: clean_client mbedtls_clean clean_test

clean_test:
	rm -f test_crypto_utils test_serializer test_tryte_byte_conv

clean_client:
	rm -f ta_client *.o

mbedtls_clean:
	@for dir in $(MBEDTLS); do \
		$(MAKE) -C $$dir clean; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done