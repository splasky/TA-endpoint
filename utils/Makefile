INCLUDES := -I$(THIRD_PARTY_PATH)/openssl/include
OBJS = crypto_utils.o serializer.o tryte_byte_conv.o uart_utils.o

ifeq ($(KEY_DEBUG), n)
UTILS_CFLAGS = $(CFLAGS)
else
UTILS_CFLAGS = $(CFLAGS) -DKEY_DEBUG
endif

all: $(OBJS)

%.o: %.c
	$(CC) -c $(UTILS_CFLAGS) $(INCLUDES) -o $@ $^

clean:
	rm -f *.o