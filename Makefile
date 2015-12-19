test: Main.o Rijndael.o
	gcc -o test Main.o Rijndael.o

Main.o: Main.c 
	gcc -c Main.c

Rijndael.o: Rijndael.c Rijndael.h Rijndael_Consts.h
	gcc -c Rijndael.c

.PHONY clean :
	rm *.o
	rm test
