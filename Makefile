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
TEST_PATH = $(ROOT_DIR)/tests
UTILS_PATH = $(ROOT_DIR)/utils
CONNECTIVITY_PATH = $(ROOT_DIR)/connectivity
export THIRD_PARTY_PATH ROOT_DIR UTILS_PATH

ifeq ($(DEBUG), n)
CFLAGS = -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -O2 -g3
else
CFLAGS = -fPIC -DHAVE_CONFIG_H -D_U_="__attribute__((unused))" -O2 -g3 -DDEBUG
endif
export CFLAGS

INCLUDES := -I$(THIRD_PARTY_PATH)/openssl/include -I$(THIRD_PARTY_PATH)/http-parser -I$(THIRD_PARTY_PATH)/mbedtls/include -I$(ROOT_DIR)/connectivity -I$(ROOT_DIR)/utils
LIBS = $(MBEDTLS_PATH)/library/libmbedx509.a $(MBEDTLS_PATH)/library/libmbedtls.a $(MBEDTLS_PATH)/library/libmbedcrypto.a

UTILS_OBJS = $(UTILS_PATH)/crypto_utils.o $(UTILS_PATH)/serializer.o $(UTILS_PATH)/tryte_byte_conv.o $(UTILS_PATH)/uart_utils.o
# We need to modify this rule here to be compatible to the situation 
# that we have several different ways of connectivity in the future
CONNECTIVITY_OBJS = conn_http.o

OBJS = main.o $(HTTP_PARSER_PATH)/http_parser.o $(UTILS_OBJS) $(CONNECTIVITY_OBJS)

.SUFFIXES:.c .o

all: ta_client

ta_client: mbedtls_make $(OBJS)
	@echo Linking: $@ ....
	$(CC) -o $@ $(OBJS) $(LIBS) -lcrypto

mbedtls_make:
	@for dir in $(MBEDTLS_PATH); do \
		$(MAKE) -C $$dir ; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done

conn_http.o: connectivity/conn_http.c
	@echo Compiling $@ ...
	$(CC) -v -c $(CFLAGS) $(INCLUDES) -MMD -MF conn_http.c.d -o $@ $<
-include conn_http.c.d

main.o: main.c
	@echo Compiling: $< ....
	$(MAKE) -C $(UTILS_PATH)
	$(CC) -c $(CFLAGS) $(INCLUDES) -MMD -MF main.c.d -o $@ $<

test: $(TEST_PATH)
	$(MAKE) -C $(TEST_PATH)

clean: clean_client clean_third_party clean_test

clean_test:
	$(MAKE) -C $(TEST_PATH) clean

clean_client:
	$(MAKE) -C $(UTILS_PATH) clean
	$(MAKE) -C $(CONNECTIVITY_PATH) clean
	rm -f ta_client *.o *.c.d

clean_third_party: clean_mbedtls clean_http_parser

clean_mbedtls:
	@for dir in $(MBEDTLS_PATH); do \
		$(MAKE) -C $$dir clean; \
		if [ $$? != 0 ]; then exit 1; fi; \
	done

clean_http_parser:
	$(MAKE) -C $(HTTP_PARSER_PATH) clean

-include main.c.d