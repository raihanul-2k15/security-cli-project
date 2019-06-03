#ifndef RSA_H
#define RSA_H

int rsa_key_gen(const int n_bits, const char* private_file, const char* public_file);
int rsa_encrypt_file(const char* file, const char* key_file);
int rsa_decrypt_file(const char* file, const char* key_file);
int rsa_key_check(const char* private_file, const char* public_file);

#endif