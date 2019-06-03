#include "./include/rsa.h"
#include "./include/bruteforce.h"
#include "./include/constants.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {

    int i;
    if (argc < 4) {
        printf("This tool needs command line arguments to work\n");
        printf("Usage: crypto.exe cmd algo ...\n");
        printf("Examples:\n");
        printf("crypto.exe keygen rsa 1024 private.txt public.txt\n");
        printf("crypto.exe encrypt rsa file.txt public.txt\n");
        printf("crypto.exe decrypt rsa file.txt private.txt\n");
        printf("crypto.exe passgen brute abc123 3 5 passwords.txt\n");
        return -1;
    }

    if (strcmp(argv[1], "keygen") == 0) {
        if (strcmp(argv[2], "rsa") == 0) {
            printf("Generating %d bit rsa key pair...\n", atoi(argv[3]));
            if (rsa_key_gen(atoi(argv[3]), argv[4], argv[5]) == 0 &&
                rsa_key_check(argv[4], argv[5]) == 0
                ) {
                printf("Key generated successfully\n");
            } else {
                printf("Key generation error\n");
                return -1;
            }
        } else {
            printf("Unknown algo\n");
            return -1;
        }
    } else if (strcmp(argv[1], "encrypt") == 0) {
        if (strcmp(argv[2], "rsa") == 0) {
            printf("Encrypting %s using %s...\n", argv[3], argv[4]);
            if (rsa_encrypt_file(argv[3], argv[4]) == 0) {
                printf("Encrypted successfully\n");
            } else {
                printf("An error occured\n");
                return -1;
            }
        } else {
            printf("Unknown algo\n");
            return -1;
        }
    } else if (strcmp(argv[1], "decrypt") == 0) {
        if (strcmp(argv[2], "rsa") == 0) {
            printf("Decrypting %s using %s...\n", argv[3], argv[4]);
            if (rsa_decrypt_file(argv[3], argv[4]) == 0) {
                printf("Decrypted successfully\n");
            } else {
                printf("An error occured\n");
                return -1;
            }
        } else {
            printf("Unknown algo\n");
            return -1;
        }
    } else if (strcmp(argv[1], "passgen") == 0) {
        if (strcmp(argv[2], "brute") == 0) {
            printf("Generating passwords of %d to %d length of charset %s...\n", atoi(argv[4]), atoi(argv[5]), argv[3]);
            if (bruteforce_pass_gen(argv[3], atoi(argv[4]), atoi(argv[5]), argv[6]) == 0) {
                printf("Passwords generated successfully\n");
            } else {
                printf("An error occured\n");
                return -1;
            }
        } else {
            printf("Unknown algo\n");
            return -1;
        }
    } else {
        printf("Unknown cmd\n");
        return -1;
    }

    return 0;
}

