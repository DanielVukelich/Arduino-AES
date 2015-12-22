CFLAGS = -std=c99
CC = gcc

debug:	CFLAGS += -g -DDEBUG
debug:	test

test:	Main.o Rijndael.o
	$(CC) $(CFLAGS) -o test Main.o Rijndael.o

Main.o: Main.c 
	$(CC) $(CFLAGS) -c Main.c

Rijndael.o: Rijndael.c Rijndael.h Rijndael_Consts.h
	$(CC) $(CFLAGS) -c Rijndael.c

.PHONY clean :
	rm *.o
	rm test
