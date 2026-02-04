# Parametri za SHA-256
PARAMS = sphincs-sha2-128s
THASH = robust

CC = /usr/bin/gcc
CFLAGS = -Wall -Wextra -Wpedantic -O3 -std=c99 -Wmissing-prototypes -DPARAMS=sphincs-sha2-128s `pkg-config --cflags gtk+-3.0`
LDFLAGS = `pkg-config --libs gtk+-3.0`
SOURCES = address.c randombytes.c merkle.c wots.c wotsx1.c utils.c utilsx1.c fors.c sign.c main.c sha2.c hash_sha2.c thash_sha2_robust.c
OUTPUT = sphincs_app

all: $(OUTPUT)

$(OUTPUT): $(SOURCES)
	$(CC) $(CFLAGS) $(SOURCES) -o $(OUTPUT) $(LDFLAGS)

clean:
	rm -f $(OUTPUT)

