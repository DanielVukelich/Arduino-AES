# Arduino-AES
A small library for the arduino that implements the AES (Rijndael) Cryptrosystem

I originally wrote this for the arduino.  To that end, I've written it to use as few libraries as possible.  This means that it's not very memory safe.  However, if it's on an embedded device like an arduino, whoever is using it should have lots of control over how it's used, so there shouldn't be a problem.  I chose C instead of C++ because I may want to use this simple library in my operating system, DOSDOS.

It implements AES-128, AES-192, and AES-256.  Usage is simple, you generate your key schedule based off of a key, and then you can encrypt/decrypt messages.

Here's a brief rundown of the exposed components:
    
    enum RIJNDAEL_TYPE
  This enum determines which AES encryption mode you're using.  Possible values are
  
    AES_128
    AES_192
    AES_256
  For 128 bit keys, 192 bit keys, and 256 bit keys respectively
  
    void Schedule_Keys(enum RIJNDAEL_TYPE type, const unsigned char* key, const int keylen, unsigned char* sched_keys);
  This is the key scheduling function.  type tells the function how large your keys are.  key is a pointer to an unsigned char array containing the key that will be expanded.  keylen is the length of that key.  Keylen cannot be longer than 16, 24, or 32 for 128-bit, 192-bit, or 256-bit AES respectively.  If keylen is less than one of those values, the key will be repeated until it is of sufficient length.  Lastly, sched_keys is the pointer to the array of unsigned chars that will hold your scheduled keys by the end.  sched_keys must be of size 176, 208, or 240 for 128-bit, 192-bit, and 256-bit AES respectively.
  
  
    void Encrypt(enum RIJNDAEL_TYPE type, const unsigned char* plaintext, const int plaintext_len, const unsigned char* keys,  unsigned char* cipher);
  type is the encryption mode you want to encrypt with.  Plaintext is a pointer to an array of unsigned characters that signify your un-encrypted message.  plaintext_len is the length of your plaintext.  Note that your plaintext MUST have a length that is a multiple of 16.  keys is a pointer to the unsigned character array containing your previously scheduled keys.  Lastly, cipher is an unsigned character array where you want the ciphertext to go.  cipher must have an identical size to plaintext.
  
    void Decrypt(enum RIJNDAEL_TYPE type, const unsigned char* ciphertext, const int plaintext_len, const unsigned char* keys,  unsigned char* plain);
  The decrypt function functions similarly to encrypt, except you pass a ciphertext in place of the plaintext, and it fills a plaintext array with the decrypted message.
  
  Project is licensed with the LGPL 3.
