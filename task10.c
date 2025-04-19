#define OPENSSL_SUPPRESS_DEPRECATED
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/des.h>
#include <time.h>

#define SALT_SIZE 2
#define ENCRYT_ROUNDS 25    


void generate_salt(unsigned char *salt){
    salt[0] = rand() % 256;
    salt[1] = rand() % 256;
}

void derive_key(const char *password, unsigned char *salt, DES_cblock *key){
    unsigned char temp_key[8] = {0};
    size_t pw_len = strlen(password);
    for(int i=0; i<6 && i <pw_len;i++){
        temp_key[i] = password[i];
    }

    temp_key[6] = salt[0];
    temp_key[7] = salt[1];

    memcpy(key, temp_key, 8);
}

void encrypt_password (const char *password, unsigned char *salt, unsigned char *out){
    DES_cblock key;
    DES_key_schedule schedule;
    derive_key(password, salt, &key);
    DES_set_key_unchecked(&key, &schedule);
    DES_cblock block = {0};
    DES_cblock result;
    memcpy(&result, &block, sizeof(DES_cblock) );
    
    for(int i = 0; i< ENCRYT_ROUNDS; i++){
        DES_ecb_encrypt(&result, &result, &schedule, DES_ENCRYPT);
    }
    memcpy(out, result, sizeof(DES_cblock));
}

int verify_password(const char *input_password, unsigned char *salt, unsigned char *stored_hash){
    unsigned char computed_hash[8];
    encrypt_password(input_password, salt, computed_hash);
    return memcmp(computed_hash, stored_hash, 8) == 0;
}

void print_hash(unsigned char *salt, unsigned char *hash){
    printf("salt: %02x%02x | hash: ", salt[0], salt[1]);
    for(int i =0; i<8;i++){
        printf("%02x", hash[i]);
    }
    printf("\n");
}
int main(){
    srand(time(NULL));
    char *passwords[10] = {
        "assal1", "muffins", "encrypt","hello1","assddkj",
        "mykitty","tunaaas","dawgsss","batman","kitties"
    };

    for(int i = 0; i<10; i++){
        unsigned char salt[SALT_SIZE];
        unsigned char hash[8];

        generate_salt(salt);
        encrypt_password(passwords[i], salt, hash);
        printf("password: %-10s ", passwords[i]);
        print_hash(salt,hash);
    }
    return 0;
}