INCLUDES := -I$(THIRD_PARTY_PATH)/mbedtls/include -I$(THIRD_PARTY_PATH)/http-parser -I$(ROOT_DIR)/utils

all: conn_http.o

.NOTPARALLEL:
connectivity/conn_http.o: conn_http.c
	@echo Compiling $@ ...
	$(CC) -fPIC -c $(CFLAGS) $(INCLUDES) -MMD -MF conn_http.c.d -o $@ $<

clean:
	rm -f *.o *.c.d

-include conn_http.c.d