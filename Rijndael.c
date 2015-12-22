#include "Rijndael_Consts.h"
#include "Rijndael.h"

//Rotates a 4 byte word amount bytes to the left
void Rotate(const int amount, unsigned char* input){
  for(int i = 0; i < amount; ++i){
    unsigned char temp = input[0];
    input[0] = input[1];
    input[1] = input[2];
    input[2] = input[3];
    input[3] = temp;
  }
  return;
}

void KS_Core(const unsigned char iteration, unsigned char* input){
  Rotate(1, input);
  for(int i = 0; i < 4; ++i){
    input[i] = SBOX[input[i]];
  }
  input[0] = input[0] ^ RCON[iteration];
}

void KS_XOR(const unsigned char* temp, unsigned char* sched_keys, const int ksiz, int sk_iter){
  //++sk_iter;
  for(int i = 0; i < 4; ++i){
    sched_keys[sk_iter + i] = sched_keys[sk_iter + i - ksiz] ^ temp[i];
  }
  return;
}

void temp_getprev(unsigned char* temp, const unsigned char* sched_keys, int sk_iter){
  for(int i = 0; i < 4; ++i){
    temp[i] = sched_keys[sk_iter - (3 - i) - 1];
  }
  return;
}

void Schedule_Keys(enum RIJNDAEL_TYPE type, const unsigned char* key, const int keylen, unsigned char* sched_keys){

  //Set up the various variables that depend on our keysize
  int ksiz, numbytes, lastprocess;
  switch(type){
  case AES_128:
    ksiz = 16;
    numbytes = 176;
    lastprocess = 0;
    break;
  case AES_192:
    ksiz = 24;
    numbytes = 208;
    lastprocess = 2;
    break;
  case AES_256:
    ksiz = 32;
    numbytes = 240;
    lastprocess = 3;
    break;
  default:
    ksiz = 0;
    numbytes = 0;
    lastprocess = 0;
  }

  int bytes_generated = ksiz;
  //Copy our key into the first ksiz bytes, repeating if necessary
  for(int i = 0; i < ksiz; ++i){
    sched_keys[i] = key[i % keylen];
  }
  
  int rcon_iter = 1;

  unsigned char temp[4];
  while(bytes_generated < numbytes){
    temp_getprev(temp, sched_keys, bytes_generated);
    KS_Core(rcon_iter, temp);
    ++rcon_iter;
    KS_XOR(temp, sched_keys, ksiz, bytes_generated);
    bytes_generated += 4;
    for(int i = 0; i < 3 && bytes_generated < numbytes; ++i, bytes_generated += 4){
      temp_getprev(temp, sched_keys, bytes_generated);
      KS_XOR(temp, sched_keys, ksiz, bytes_generated);
    }
    if(type == AES_256 && bytes_generated < numbytes){
      temp_getprev(temp, sched_keys, bytes_generated);
      for(int i = 0; i < 4; ++i)
	temp[i] = SBOX[temp[i]];
      KS_XOR(temp, sched_keys, ksiz, bytes_generated);
      bytes_generated += 4;
    }
    for(int i = 0; i < lastprocess && bytes_generated != numbytes; ++i, bytes_generated += 4){
      temp_getprev(temp, sched_keys, bytes_generated);
      KS_XOR(temp, sched_keys, ksiz, bytes_generated);
    }
  }
  return;
}

void sub_bytes(unsigned char box[4][4], int inv){
  const unsigned char* lookupTable = SBOX;
  if(inv)
    lookupTable = SBOX_INVERSE;
  for(int col = 0; col < 4; ++col){
    for(int row = 0; row < 4; ++row){
      box[col][row] = lookupTable[box[col][row]];
    }
  }
  return;
}

void shift_rows(unsigned char box[4][4], int inv){
  for(int shift = 1; shift < 4; ++shift){
    if(inv)
      Rotate(shift, box[4 - shift]);
    else
      Rotate(shift, box[shift]);
  }
  return;
}

void mix_cols(unsigned char box[4][4], int inv){
  unsigned char tbox[4][4];
  const unsigned char* mult_values = MIX_COL;
  if(inv)
    mult_values = MIX_COL_INV;
  
  for(int trow = 0; trow < 4; ++trow){
    for(int tcol = 0; tcol < 4; ++tcol){
      int sum = 0;
      for(int i = 0; i < 4; ++i){
	int mplier = box[i][tcol];
	int mcand = mult_values[(trow * 4) + (i * 1)];
	int result = mplier;
	switch(mcand){
	case 2:
	  result = GF_MUL_2[mplier];
	  break;
	case 3:
	  result = GF_MUL_3[mplier];
	  break;
	case 9:
	  result = GF_MUL_9[mplier];
	  break;
	case 11:
	  result = GF_MUL_11[mplier];
	  break;
	case 13:
	  result = GF_MUL_13[mplier];
	  break;
	case 14:
	  result = GF_MUL_14[mplier];
	  break;
	}
	sum ^= result;
      }
      tbox[trow][tcol] = sum;
    }
  }
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++ col){
      box[row][col] = tbox[row][col];
    }
  }
  return;
}

void add_keys(unsigned char box[4][4], const unsigned char* keys, const int round){
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++col){
      box[col][row] ^= keys[16 * round + ((4 * row) + col)];
    }
  }
  return;
}

//Assumes plaintext has already been padded to have length of multiple 16
void Encrypt(enum RIJNDAEL_TYPE type, const unsigned char* plaintext, const int plaintext_len, const unsigned char* keys,  unsigned char* cipher){
  for(int i = 0; i < plaintext_len; i += 16){
    Encrypt_Block(type, plaintext + i, keys, cipher + i);
  }
}

void Decrypt(enum RIJNDAEL_TYPE type, const unsigned char* ciphertext, const int plaintext_len, const unsigned char* keys,  unsigned char* plain){
  for(int i = 0; i < plaintext_len; i += 16){
    Decrypt_Block(type, ciphertext + i, keys, plain + i);
  }
}

void Encrypt_Block(enum RIJNDAEL_TYPE type, const unsigned char* plaintext, const unsigned char* keys, unsigned char* cipher){
  unsigned char box[4][4];
  int rounds = 0;
  switch(type){
  case AES_128:
    rounds = 10;
    break;
  case AES_192:
    rounds = 12;
    break;
  case AES_256:
    rounds = 14;
    break;
  }

  //Load our plaintext into the 4x4 byte array and immediately add the initial round key
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++col){
      box[col][row] = plaintext[4 * row + col] ^ keys[(4 * row + col)];
    }
  }

  //Perform our round operations
  for(int curround = 1; curround <= rounds; ++curround){
    sub_bytes(box, 0);
    shift_rows(box, 0);
    if(curround != rounds)
      mix_cols(box, 0);
    add_keys(box, keys, curround);
  }
  
  //Copy the 4x4 array into our ciphertext
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++col){
      cipher[4 * row + col] = box[col][row];
    }
  }
  
  return;
}

void Decrypt_Block(enum RIJNDAEL_TYPE type, const unsigned char* ciphertext, const unsigned char* keys, unsigned char* plain){
  unsigned char box[4][4];
  int rounds = 0;
  switch(type){
  case AES_128:
    rounds = 10;
    break;
  case AES_192:
    rounds = 12;
    break;
  case AES_256:
    rounds = 14;
    break;
  }
  
    //Load our ciphertext into the 4x4 byte array and immediately add the initial round key
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++col){
      box[col][row] = ciphertext[4 * row + col] ^ keys[(rounds) * 16 + (4 * row + col)];
    }
  }
  
  //Perform our round operations
  for(int curround = rounds - 1; curround >= 0; --curround){
    shift_rows(box, 1);
    sub_bytes(box, 1);
    add_keys(box, keys, curround);
    if(curround != 0)
      mix_cols(box, 1);
  }
  
  //Copy the 4x4 array into our plaintext
  for(int row = 0; row < 4; ++row){
    for(int col = 0; col < 4; ++col){
      plain[4 * row + col] = box[col][row];
    }
  }
  
  return;
}
