CFLAGS = -std=c99

test: Main.o Rijndael.o
	gcc $(CFLAGS) -o test Main.o Rijndael.o

Main.o: Main.c 
	gcc $(CFLAGS) -c Main.c

Rijndael.o: Rijndael.c Rijndael.h Rijndael_Consts.h
	gcc $(CFLAGS) -c Rijndael.c

.PHONY clean :
	rm *.o
	rm test
