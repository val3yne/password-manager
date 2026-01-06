#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define KEY_LEN 32
#define IV_LEN 16
#define SALT_LEN 16
#define TAG_LEN 16

#define SALT_FILE "vault.salt"
#define MASTER_HASH_FILE "vault.master"

static unsigned char master_key[KEY_LEN];

void hash_master(const char *pass, unsigned char *salt, unsigned char *out) {
    PKCS5_PBKDF2_HMAC(pass, strlen(pass),
        salt, SALT_LEN,
        100000, EVP_sha256(), KEY_LEN, out);
}

int verify_master(char *out_master) {
    unsigned char stored_hash[KEY_LEN], entered_hash[KEY_LEN];
    unsigned char salt[SALT_LEN];
    char input[256];
    
    FILE *fp = fopen(MASTER_HASH_FILE, "rb");
    if (!fp) {
        printf("Create master password (min 8 characters): ");
        fgets(input, sizeof(input), stdin);
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) < 8) {
            printf("Password must be at least 8 characters!\n");
            return 0;
        }
        
        if (RAND_bytes(salt, SALT_LEN) != 1) {
            printf("Error generating salt!\n");
            return 0;
        }
        
        hash_master(input, salt, stored_hash);
        
        FILE *salt_fp = fopen(SALT_FILE, "wb");
        if (!salt_fp) {
            printf("Error saving salt!\n");
            return 0;
        }
        fwrite(salt, 1, SALT_LEN, salt_fp);
        fclose(salt_fp);
        
        fp = fopen(MASTER_HASH_FILE, "wb");
        if (!fp) {
            printf("Error saving master hash!\n");
            return 0;
        }
        fwrite(stored_hash, 1, KEY_LEN, fp);
        fclose(fp);
        
        strcpy(out_master, input);
        memset(input, 0, sizeof(input));
        
        printf("Master password created successfully!\n");
        return 1;
    }
    
    FILE *salt_fp = fopen(SALT_FILE, "rb");
    if (!salt_fp) {
        printf("Error: Salt file missing!\n");
        fclose(fp);
        return 0;
    }
    fread(salt, 1, SALT_LEN, salt_fp);
    fclose(salt_fp);
    
    fread(stored_hash, 1, KEY_LEN, fp);
    fclose(fp);
    
    printf("Enter master password: ");
    fgets(input, sizeof(input), stdin);
    input[strcspn(input, "\n")] = 0;
    
    hash_master(input, salt, entered_hash);
    
    int match = (memcmp(stored_hash, entered_hash, KEY_LEN) == 0);
    
    if (match) {
        strcpy(out_master, input);
    }
    
    memset(input, 0, sizeof(input));
    memset(entered_hash, 0, KEY_LEN);
    
    return match;
}

void init_crypto(const char *master) {
    unsigned char salt[SALT_LEN];
    
    FILE *fp = fopen(SALT_FILE, "rb");
    if (fp) {
        fread(salt, 1, SALT_LEN, fp);
        fclose(fp);
    }
    
    PKCS5_PBKDF2_HMAC(master, strlen(master),
        salt, SALT_LEN,
        100000, EVP_sha256(), KEY_LEN, master_key);
}

void encrypt_string(char *data) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[512];
    int len, ciphertext_len;
    
    if (RAND_bytes(iv, IV_LEN) != 1) {
        printf("Error generating IV!\n");
        return;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, (unsigned char*)data, strlen(data));
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag);
    
    EVP_CIPHER_CTX_free(ctx);
    
    char *ptr = data;
    
    for (int i = 0; i < IV_LEN; i++) {
        sprintf(ptr, "%02x", iv[i]);
        ptr += 2;
    }
    
    for (int i = 0; i < TAG_LEN; i++) {
        sprintf(ptr, "%02x", tag[i]);
        ptr += 2;
    }
    
    for (int i = 0; i < ciphertext_len; i++) {
        sprintf(ptr, "%02x", ciphertext[i]);
        ptr += 2;
    }
    *ptr = '\0';
}

void decrypt_string(char *data) {
    EVP_CIPHER_CTX *ctx;
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char ciphertext[512];
    unsigned char plaintext[512];
    int len, plaintext_len, ciphertext_len;
    
    char *ptr = data;
    
    for (int i = 0; i < IV_LEN; i++) {
        sscanf(ptr, "%2hhx", &iv[i]);
        ptr += 2;
    }
    
    for (int i = 0; i < TAG_LEN; i++) {
        sscanf(ptr, "%2hhx", &tag[i]);
        ptr += 2;
    }
    
    ciphertext_len = (strlen(data) - (IV_LEN + TAG_LEN) * 2) / 2;
    
    for (int i = 0; i < ciphertext_len; i++) {
        sscanf(ptr, "%2hhx", &ciphertext[i]);
        ptr += 2;
    }
    
    ctx = EVP_CIPHER_CTX_new();
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, master_key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, tag);
    
    int ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    
    EVP_CIPHER_CTX_free(ctx);
    
    if (ret > 0) {
        plaintext_len += len;
        plaintext[plaintext_len] = '\0';
        strcpy(data, (char*)plaintext);
    } else {
        printf("Decryption failed! Data may be corrupted.\n");
        data[0] = '\0';
    }
}
