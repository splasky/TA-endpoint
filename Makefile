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
THIRD_PARTY_PATH = $(ROOT_DIR)/third_party
MBEDTLS_PATH = $(THIRD_PARTY_PATH)/mbedtls
HTTP_PARSER_PATH = $(THIRD_PARTY_PATH)/http-parser
UNITY_PATH = $(THIRD_PARTY_PATH)/Unity
TEST_PATH = $(ROOT_DIR)/tests
UTILS_PATH = $(ROOT_DIR)/utils
CONNECTIVITY_PATH = $(ROOT_DIR)/connectivity
export THIRD_PARTY_PATH ROOT_DIR UTILS_PATH MBEDTLS_PATH UNITY_PATH

ifeq ($(DEBUG), n)
CFLAGS = -Wall -Werror -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -O2
else
CFLAGS = -Wall -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -g3 -DDEBUG
endif
export CFLAGS

INCLUDES = -I$(THIRD_PARTY_PATH)/http-parser -I$(MBEDTLS_PATH)/include -I$(ROOT_DIR)/connectivity -I$(ROOT_DIR)/utils
LIBS = $(MBEDTLS_PATH)/library/libmbedx509.a $(MBEDTLS_PATH)/library/libmbedtls.a $(MBEDTLS_PATH)/library/libmbedcrypto.a
export INCLUDES

UTILS_OBJS = $(UTILS_PATH)/crypto_utils.o $(UTILS_PATH)/serializer.o $(UTILS_PATH)/tryte_byte_conv.o \
			 $(UTILS_PATH)/uart_utils.o $(UTILS_PATH)/protocol.o $(UTILS_PATH)/trytes.o
# that we have several different ways of connectivity in the future
CONNECTIVITY_OBJS = conn_http.o

OBJS = main.o http_parser.o $(UTILS_OBJS) $(CONNECTIVITY_OBJS)
TA_LIB = libta_endpoint.so

CFLAGS += -DTA_HOST=tangle-accel.puyuma.org -DTA_PORT=434 -DTA_API=transaction/

.SUFFIXES:.c .o
.PHONY: all clean test pre-build help mbedtls_make legato

all: pre-build ta_client mbedtls_make

## Build ta-client
ta_client: mbedtls_make $(OBJS)
	@echo Linking: $@ ....
	$(CC) -o $@ $(OBJS) $(LIBS)

mbedtls_make:
	$(MAKE) -C $(MBEDTLS_PATH) lib

$(TA_LIB): mbedtls_make $(UTILS_OBJS) $(CONNECTIVITY_OBJS) http_parser.o
	$(CC) -shared -o $@ $(UTILS_OBJS) $(CONNECTIVITY_OBJS) http_parser.o $(LIBS)

conn_http.o: connectivity/conn_http.c
	@echo Compiling $@ ...
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
http_parser.o: $(THIRD_PARTY_PATH)/http-parser/http_parser.c
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
main.o: main.c $(UTILS_OBJS)
	@echo Compiling: $< ....
	$(CC) -c $(CFLAGS) $(INCLUDES) -o $@ $<
$(UTILS_OBJS):
	$(MAKE) -C $(UTILS_PATH)

## Build tests
test: $(TEST_PATH) $(UTILS_OBJS)
	$(MAKE) -C $(TEST_PATH)

## Build ta-endpoint legato app
legato:
	make clean && make ARM=y DEBUG=n $(TA_LIB) -j$(nproc) && mkapp -v -t wp77xx ta-endpoint.adef

## Prints help for targets with comments
help:
	@cat $(MAKEFILE_LIST)| \
		awk '/^##.*$$/{l1=$$0;getline;l2=(l1 "##" $$0); print l2 $$0}' | \
		awk -F"##" '{split($$3,t,":");printf "\033[36m%-30s\033[0m %s\n",t[1],$$2}'

## Clean the directory
clean: clean_client clean_third_party clean_test clean_build_app

clean_test:
	$(MAKE) -C $(TEST_PATH) clean

clean_client:
	$(MAKE) -C $(UTILS_PATH) clean
	$(MAKE) -C $(CONNECTIVITY_PATH) clean
	rm -f ta_client *.o *.c.d $(TA_LIB)

clean_build_app:
	rm -rf _build_* *.update

clean_third_party: clean_mbedtls clean_http_parser

clean_mbedtls:
	@for dir in $(MBEDTLS_PATH); do \
		$(MAKE) -C $$dir clean; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done

clean_http_parser:
	$(MAKE) -C $(HTTP_PARSER_PATH) clean

pre-build:
	git config core.hooksPath hooks
