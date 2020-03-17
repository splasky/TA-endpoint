OBJS = crypto_utils.o serializer.o tryte_byte_conv.o uart_utils.o
all: $(OBJS)

%.o: %.c
	$(CC) -c $(UTILS_CFLAGS) $(INCLUDES) -o $@ $^

clean:
	rm -f *.o
