enum RIJNDAEL_TYPE {
  AES_128,
  AES_192,
  AES_256
};

void Schedule_Keys(enum RIJNDAEL_TYPE, const unsigned char*, const int, unsigned char*);

void Encrypt(enum RIJNDAEL_TYPE, const unsigned char*, const int, const unsigned char*, unsigned char*);

void Decrypt(enum RIJNDAEL_TYPE, const unsigned char*, const int, const unsigned char*,  unsigned char*);

void Encrypt_Block(enum RIJNDAEL_TYPE, const unsigned char*, const unsigned char*, unsigned char*);

void Decrypt_Block(enum RIJNDAEL_TYPE, const unsigned char*, const unsigned char*, unsigned char*);
