#include <openssl/aes.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>

#define charMaxLeng 20

unsigned char AscToHex(unsigned char Char) {
    int aChar = (int) Char;
    if ((aChar >= 0x30) && (aChar <= 0x39))
        aChar -= 0x30;
    else if ((aChar >= 0x41) && (aChar <= 0x46))
        aChar -= 0x37;
    else if ((aChar >= 0x61) && (aChar <= 0x66))
        aChar -= 0x57;
    else
        aChar = 0xff;
    return aChar;
}

unsigned char HexToAsc(unsigned char aHex) {
    if ((aHex >= 0) && (aHex <= 9))
        aHex += 0x30;
    else if ((aHex >= 10) && (aHex <= 15))
        aHex += 0x37;
    else
        aHex = 0xff;
    return aHex;
}

unsigned char* str2hex(char *str) {
    unsigned char *ret = NULL;
    int str_len = strlen(str);
    int i = 0;
    assert((str_len % 2) == 0);
    ret = (char *) malloc(str_len / 2);
    for (i = 0; i < str_len; i = i + 2) {
        sscanf(str + i, "%2hhx", &ret[i / 2]);
    }
    return ret;
}

char *padding_buf(char *buf, int size, int *final_size) {
    char *ret = NULL;
    int padding_size = AES_BLOCK_SIZE - (size % AES_BLOCK_SIZE);
    int i;
    *final_size = size + padding_size;
    ret = (char *) malloc(size + padding_size);
    memcpy(ret, buf, size);
    if (padding_size != 0) {
        for (i = size; i < (size + padding_size); i++) {
            ret[i] = padding_size;
        }
    }
    return ret;
}

void printf_buff(char *buff, int size) {
    int i = 0;
    for (i = 0; i < size; i++) {
        printf("%02X", (unsigned char) buff[i]);
    }
    printf("\n");
}

void encrypt_buffer(char *raw_buf, char **encrypted_output, int len, char* kkey) {
    AES_KEY aes;
    unsigned char *key = str2hex(kkey);
    unsigned char *iv = str2hex("aabbccddeeff00998877665544332211");
    AES_set_encrypt_key(key, 128, &aes);
    AES_cbc_encrypt(raw_buf, *encrypted_output, len, &aes, iv, AES_ENCRYPT);
    free(key);
    free(iv);
}

void decrypt_buf(char *raw_buf, char **decrypt_buf, int len, char* kkey) {
    AES_KEY aes;
    unsigned char *key = str2hex(kkey);
    unsigned char *iv = str2hex("aabbccddeeff00998877665544332211");
    AES_set_decrypt_key(key, 128, &aes);
    AES_cbc_encrypt(raw_buf, *decrypt_buf, len, &aes, iv, AES_DECRYPT);
    free(key);
    free(iv);
}

int main(int argc, char* argv[]) {
    char* target = "764AA26B55A4DA654DF6B19E4BCE00F4ED05E09346FB0E762583CB7DA2AC93A2";
    FILE* p = NULL;

    if ((p = fopen("words.txt", "r")) == NULL) {
        printf("ERROR\n");
        return 1;
    }

    char buffer[charMaxLeng];
    char buf2[charMaxLeng];
    int flag = 0;

    while (!feof(p)) {
        int i = 0;
        memset(buffer, '\0', charMaxLeng * sizeof(char));
        memset(buf2, '\0', charMaxLeng * sizeof(char));
        fgets(buffer, charMaxLeng, p);

        while (i < charMaxLeng) {
            buf2[i] = buffer[i];
            i += 1;
        }

        size_t len = strlen(buffer);
        if (len == 1) continue;

        char *raw_buf = NULL;
        char *after_padding_buf = NULL;
        int padding_size = 0;
        char *encrypted_output = NULL;
        char *decrypt_buf = NULL;

        i = 0;
        unsigned char* key = NULL;
        key = (unsigned char*) malloc(33);

        while (i < strlen(buffer)) {
            unsigned char letter = buffer[i];
            key[2 * i] = HexToAsc(letter / 0x10);
            key[2 * i + 1] = HexToAsc(letter % 0x10);
            ++i;
            if (i == 0x0f || buffer[i] < 0x20) break;
        }

        while (i < 0x10) {
            key[2 * i] = '2';
            key[2 * i + 1] = '3';
            ++i;
        }

        key[0x20] = '\0';
        raw_buf = (char *) malloc(21);
        memcpy(raw_buf, "This is a top secret.", 21);

        after_padding_buf = padding_buf(raw_buf, 21, &padding_size);
        encrypted_output = (char *) malloc(padding_size);

        encrypt_buffer(after_padding_buf, &encrypted_output, padding_size, key);

        i = 0;
        char temp = '\0';
        flag = 1;

        while (i < padding_size) {
            temp = HexToAsc((unsigned char) encrypted_output[i] / 0x10);
            if (temp != target[2 * i]) {
                flag = 0;
                break;
            }
            temp = HexToAsc((unsigned char) encrypted_output[i] % 0x10);
            if (temp != target[2 * i + 1]) {
                flag = 0;
                break;
            }
            i += 1;
        }

        if (flag == 0) {
            continue;
        }

        printf("%s", buf2);
        //printf_buff(encrypted_output, padding_size);
        printf("%s\n", target);

        free(raw_buf);
        free(after_padding_buf);
        free(encrypted_output);
        free(decrypt_buf);
        break;
    }

    fclose(p);
    return 0;
}
