#include "./include/rsa.h"
#include "./include/constants.h"
#include "./include/gmp.h"
#include <stdio.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <time.h>

void xor_str(char*, char);

int rsa_key_gen(const int n_bits, const char* private_file, const char* public_file) {
    srand(time(0));
    mpz_t p, q, n, phi, gcd, p_1, q_1, e, d;
    mpz_init(p);
    mpz_init(q);
    mpz_init_set_ui(n, 1);
    mpz_init(phi);
    mpz_init_set_ui(gcd, 0);
    mpz_init(p_1);
    mpz_init(q_1);
    mpz_init_set_ui(e, 1);
    mpz_init(d);

    int p_bits = n_bits / 2, i;
    char *p_str = (char *) malloc(p_bits + 1);
    p_str[0] = '1';
    for (i=0; i<p_bits; i++) p_str[i] = (char)(rand() % 2 + '0');
    p_str[p_bits] = '\0';
    mpz_set_str(p, p_str, 2);
    mpz_nextprime(p, p);
    mpz_ui_pow_ui(q, 2, n_bits / 4);
    while (mpz_sizeinbase(n, 2) < n_bits) {
        mpz_mul_ui(q, q, 2);
        mpz_nextprime(q, q);
        mpz_mul(n, p, q);
    }
    mpz_sub_ui(p_1, p, 1);
    mpz_sub_ui(q_1, q, 1);
    mpz_mul(phi, p_1, q_1);

    printf("%d %d %d\n", mpz_sizeinbase(p, 2), mpz_sizeinbase(q, 2), mpz_sizeinbase(n, 2));

    while(mpz_cmp_ui(gcd, 1) != 0) {
        mpz_add_ui(e, e, 2);
        mpz_gcd(gcd, phi, e);
    }

    if (!mpz_invert(d, e, phi)) 
        return KEY_ERROR;

    char* d_str = mpz_get_str(NULL, 10, d);
    char* e_str = mpz_get_str(NULL, 10, e);
    char* n_str = mpz_get_str(NULL, 10, n);
    xor_str(d_str, 38);
    xor_str(e_str, 38);
    xor_str(n_str, 38);
    FILE *priv = fopen(private_file, "wb");
    FILE *pub = fopen(public_file, "w");
    fprintf(priv, "%s\n%s", d_str, n_str);
    fprintf(pub, "%s\n%s", e_str, n_str);
    fclose(priv);
    fclose(pub);
    
    free(p_str);
    mpz_clear(p);
    mpz_clear(q);
    mpz_clear(n);
    mpz_clear(phi);
    mpz_clear(gcd);
    mpz_clear(p_1);
    mpz_clear(q_1);
    mpz_clear(e);
    mpz_clear(d);

    return 0;
}

int rsa_encrypt_file(const char* file, const char* key_file) {
    FILE *f, *kf, *ef;
    char* encrypted_file = (char *) malloc(strlen(file) + 4);
    strcpy(encrypted_file, file);
    strcpy(encrypted_file+strlen(file), "___");

    if (!(f = fopen(file, "rb")))
        return FILE_NOT_FOUND;
    if (!(kf = fopen(key_file, "r")))
        return KEY_FILE_NOT_FOUND;
    ef = fopen(encrypted_file, "wb");
    
    mpz_t e, n, msg, cypher;
    mpz_init(e); 
    mpz_init(n);
    mpz_init(msg);
    mpz_init(cypher);
    
    char e_str[2049], n_str[2049];
    fscanf(kf, "%s\n%s", &e_str, &n_str);
    xor_str(e_str, 38);
    xor_str(n_str, 38);
    if (mpz_set_str(e, e_str, 10))
        return KEY_ERROR;
    if (mpz_set_str(n, n_str, 10))
        return KEY_ERROR;
    fclose(kf);

    int block_size = mpz_sizeinbase(n, 2) / 8; // no of bytes
    char* block = (char *) malloc(block_size);
    char c = 0;
    int i, read_count;
    do {
        for (i=0; i<block_size; i++) block[i] = 0;
        read_count = fread(block, 1, block_size - 1, f);
        mpz_import(msg, block_size, -1, sizeof(block[0]), 1, 0, block);
        mpz_powm(cypher, msg, e, n);
        for (i=0; i<block_size; i++) block[i] = 0;
        size_t _;
        mpz_export(block, &_, -1, sizeof(block[0]), 1, 0, cypher);
        fwrite(block, 1, block_size, ef);
    } while (read_count == block_size - 1);
    mpz_set_ui(cypher, read_count);
    mpz_out_str(ef, 16, cypher); // no of bytes of last block

    mpz_clear(e);
    mpz_clear(n);
    mpz_clear(msg);
    mpz_clear(cypher);

    fclose(f);
    fclose(ef);
    free(block);

    remove(file);
    rename(encrypted_file, file);

    return 0;
}

int rsa_decrypt_file(const char* file, const char* key_file) {
    FILE *f, *kf, *df;
    char* decrypted_file = (char *) malloc(strlen(file) + 4);
    strcpy(decrypted_file, file);
    strcpy(decrypted_file+strlen(file), "___");

    if (!(f = fopen(file, "rb")))
        return FILE_NOT_FOUND;
    if (!(kf = fopen(key_file, "r")))
        return KEY_FILE_NOT_FOUND;
    df = fopen(decrypted_file, "wb");
    
    mpz_t d, n, msg, cypher;
    mpz_init(d); 
    mpz_init(n);
    mpz_init(msg);
    mpz_init(cypher);

    char d_str[2049], n_str[2049];
    fscanf(kf, "%s\n%s", &d_str, &n_str);
    xor_str(d_str, 38);
    xor_str(n_str, 38);
    if (mpz_set_str(d, d_str, 10))
        return KEY_ERROR;
    if (mpz_set_str(n, n_str, 10))
        return KEY_ERROR;
    fclose(kf);
    
    int block_size = mpz_sizeinbase(n, 2) / 8; // no of bytes
    char* block = (char *) malloc(block_size);
    char c = 0;
    int i, read_count;
    for (i=0; i<block_size; i++) block[i] = 0;
    while ((read_count = fread(block, 1, block_size, f)) == block_size) {
        mpz_import(cypher, block_size, -1, sizeof(block[0]), 1, 0, block);
        mpz_powm(msg, cypher, d, n);
        size_t _;
        for (i=0; i<block_size; i++) block[i] = 0;
        mpz_export(block, &_, -1, sizeof(block[0]), 1, 0, msg);
        fwrite(block, 1, block_size-1, df);
        for (i=0; i<block_size; i++) block[i] = 0;
    }
    mpz_set_str(msg, block, 16);
    read_count = mpz_get_ui(msg);
    fseek(df,-(block_size - 1 - read_count),SEEK_END);
    ftruncate(fileno(df), ftell(df));

    mpz_clear(d);
    mpz_clear(n);
    mpz_clear(msg);
    mpz_clear(cypher);

    fclose(f);
    fclose(df);
    free(block);
    
    remove(file);
    rename(decrypted_file, file);

    return 0;
}

int rsa_key_check(const char* private_file, const char* public_file) {
    FILE *priv, *pub;

    if (!(priv = fopen(private_file, "r")))
        return KEY_FILE_NOT_FOUND;
    if (!(pub = fopen(public_file, "r")))
        return KEY_FILE_NOT_FOUND;

    mpz_t e, d, n, msg, cypher;
    mpz_init(e);
    mpz_init(d);
    mpz_init(n);

    char d_str[2049], e_str[2049], n_str[2049];
    fscanf(priv, "%s\n%s", &d_str, &n_str);
    fscanf(pub, "%s", &e_str);
    xor_str(d_str, 38);
    xor_str(e_str, 38);
    xor_str(n_str, 38);
       
    if (mpz_set_str(d, d_str, 10))
        return KEY_ERROR;
    if (mpz_set_str(e, e_str, 10))
        return KEY_ERROR;
    if (mpz_set_str(n, n_str, 10))
        return KEY_ERROR;
    
    fclose(priv);
    fclose(pub);

    int sample = 2;
    mpz_init_set_ui(msg, sample);
    mpz_init(cypher);
    mpz_powm(cypher, msg, e, n);
    mpz_powm(msg, cypher, d, n);
    if (sample == mpz_get_ui(msg))
        return 0;
    else
        return -1;
}

void xor_str(char* str, char pass) {
    int i, l = strlen(str);
    for (i=0; i<l; i++) str[i] = str[i] ^ pass;
}