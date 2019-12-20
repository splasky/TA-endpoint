INCLUDES := -I$(UTILS_PATH)
DIR_BUILD = build

all: create_dir build/test_tryte_byte_conv build/test_crypto_utils build/test_serializer

create_dir:
	[ -d $(DIR_BUILD) ] || mkdir -p $(DIR_BUILD)

build/test_tryte_byte_conv: test_tryte_byte_conv.c
	$(CC) -g $(INCLUDES) -o $@ $^ $(UTILS_PATH)/tryte_byte_conv.c

build/test_crypto_utils: test_crypto_utils.c
	$(CC) -g $(INCLUDES) -o $@ $^ $(UTILS_PATH)/crypto_utils.c -lcrypto

build/test_serializer: test_serializer.c
	$(CC) -g $(INCLUDES) -o $@ $^ $(UTILS_PATH)/serializer.c

clean:
	rm -f *.o
	rm -f build/*