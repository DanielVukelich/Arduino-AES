#include <stdio.h>

#include "Rijndael.h"

unsigned char key[32] = {
    0x00, 0x01, 0x02, 0x03,
    0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b,
    0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13,
    0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f
  };
  
  unsigned char text[16] = {
    0x00, 0x11, 0x22, 0x33,
    0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xAA, 0xBB,
    0xCC, 0xDD, 0xEE, 0xFF
  };

  unsigned char vect[16] = {
    0x8E, 0xA2, 0xB7, 0xCA,
    0x51, 0x67, 0x45, 0xBF,
    0xEA, 0xFC, 0x49, 0x90,
    0x4B, 0x49, 0x60, 0x89
  };
  

int main(){
  printf("Original Plaintext:\n");
  for(int i = 0; i < 16; ++i){
    printf("%2.2X ", text[i]);
  }
  
  unsigned char keys[240];
  Schedule_Keys(AES_256, key, 32, keys);
  
  unsigned char cipher[16];
  Encrypt(AES_256, text, 16, keys, cipher);

  printf("\n\nCiphertext:\n");
  for(int i = 0; i < 16; ++i){
    printf("%2.2X ", cipher[i]);
  }

  unsigned char plain[16];
  Decrypt(AES_256, cipher, 16, keys, plain);

  printf("\n\nDecrypted Plaintext:\n");
  for(int i = 0; i < 16; ++i){
    printf("%2.2X ", plain[i]);
  }

  //Does it pass the AES published test vectors?
  for(int i = 0; i < 16; ++i){
  if(cipher[i] != vect[i]){
      printf("\nEncrypted message does not match vector!\n");
      return 1;
    }
  }

  for(int i = 0; i < 16; ++i){
    if(plain[i] != text[i]){
      printf("\nDecrypted message does not match original plaintext!\n");
      return 1;
    }
  }
  
  printf("\n\nTests Passed!\n");
  return 0;
}
