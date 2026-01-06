#include <stdio.h>
#include <string.h>
#include "encrypt.h"
#include "file_ops.h"

#define MAX_INPUT 256
#define VAULT_FILE "passwords.dat"

void get_secure_input(const char *prompt, char *buffer, size_t size) {
    printf("%s", prompt);
    if (fgets(buffer, size, stdin) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
    }
}

void add_password() {
    char site[MAX_INPUT];
    char username[MAX_INPUT];
    char password[MAX_INPUT];
    
    get_secure_input("Enter site name: ", site, sizeof(site));
    
    if (strlen(site) == 0) {
        printf("Site name cannot be empty!\n");
        return;
    }
    
    get_secure_input("Enter username: ", username, sizeof(username));
    
    if (strlen(username) == 0) {
        printf("Username cannot be empty!\n");
        return;
    }
    
    get_secure_input("Enter password: ", password, sizeof(password));
    
    if (strlen(password) < 4) {
        printf("Password must be at least 4 characters!\n");
        memset(password, 0, sizeof(password));
        return;
    }
    
    char encrypted_site[MAX_INPUT * 2];
    char encrypted_username[MAX_INPUT * 2];
    char encrypted_password[MAX_INPUT * 2];
    
    strcpy(encrypted_site, site);
    strcpy(encrypted_username, username);
    strcpy(encrypted_password, password);
    
    encrypt_string(encrypted_site);
    encrypt_string(encrypted_username);
    encrypt_string(encrypted_password);
    
    FILE *fp = fopen(VAULT_FILE, "a");
    if (fp == NULL) {
        printf("Error: Cannot open vault file!\n");
        memset(password, 0, sizeof(password));
        return;
    }
    
    fprintf(fp, "%s|%s|%s\n", encrypted_site, encrypted_username, encrypted_password);
    fclose(fp);
    
    printf("✓ Password added successfully!\n");
    
    memset(password, 0, sizeof(password));
    memset(encrypted_password, 0, sizeof(encrypted_password));
}

void view_passwords() {
    FILE *fp = fopen(VAULT_FILE, "r");
    if (fp == NULL) {
        printf("No passwords saved yet.\n");
        return;
    }
    
    char line[MAX_INPUT * 6];
    char encrypted_site[MAX_INPUT * 2];
    char encrypted_username[MAX_INPUT * 2];
    char encrypted_password[MAX_INPUT * 2];
    
   
    printf(" SAVED PASSWORDS \n");
   
    
    int count = 0;
    
    while (fgets(line, sizeof(line), fp) != NULL) {
        line[strcspn(line, "\n")] = 0;
        
        char *token1 = strtok(line, "|");
        char *token2 = strtok(NULL, "|");
        char *token3 = strtok(NULL, "|");
        
        if (token1 == NULL || token2 == NULL || token3 == NULL) {
            continue;
        }
        
        strncpy(encrypted_site, token1, sizeof(encrypted_site) - 1);
        strncpy(encrypted_username, token2, sizeof(encrypted_username) - 1);
        strncpy(encrypted_password, token3, sizeof(encrypted_password) - 1);
        
        char decrypted_site[MAX_INPUT];
        char decrypted_username[MAX_INPUT];
        char decrypted_password[MAX_INPUT];
        
        strcpy(decrypted_site, encrypted_site);
        strcpy(decrypted_username, encrypted_username);
        strcpy(decrypted_password, encrypted_password);
        
        decrypt_string(decrypted_site);
        decrypt_string(decrypted_username);
        decrypt_string(decrypted_password);
        
        count++;
        printf("[%d] Site: %s\n", count, decrypted_site);
        printf("    Username: %s\n", decrypted_username);
        printf("    Password: %s\n", decrypted_password);
       
        memset(decrypted_password, 0, sizeof(decrypted_password));
    }
    
    fclose(fp);
    
    if (count == 0) {
        printf("No passwords found.\n");
    }
    
    printf("\n");
}

void delete_password() {
    char site_to_delete[MAX_INPUT];
    
    printf("\nCurrent sites:\n");
    FILE *fp_preview = fopen(VAULT_FILE, "r");
    if (fp_preview) {
        char line[MAX_INPUT * 6];
        int index = 1;
        
        while (fgets(line, sizeof(line), fp_preview) != NULL) {
            line[strcspn(line, "\n")] = 0;
            char *token = strtok(line, "|");
            if (token) {
                char site[MAX_INPUT];
                strcpy(site, token);
                decrypt_string(site);
                printf("  %d. %s\n", index++, site);
            }
        }
        fclose(fp_preview);
        printf("\n");
    }
    
    get_secure_input("Enter site name to delete: ", site_to_delete, sizeof(site_to_delete));
    
    if (strlen(site_to_delete) == 0) {
        printf("Site name cannot be empty!\n");
        return;
    }
    
    FILE *fp_read = fopen(VAULT_FILE, "r");
    if (fp_read == NULL) {
        printf("No passwords to delete.\n");
        return;
    }
    
    FILE *fp_write = fopen("temp_vault.dat", "w");
    if (fp_write == NULL) {
        printf("Error creating temporary file!\n");
        fclose(fp_read);
        return;
    }
    
    char line[MAX_INPUT * 6];
    int found = 0;
    
    while (fgets(line, sizeof(line), fp_read) != NULL) {
        char line_copy[MAX_INPUT * 6];
        strcpy(line_copy, line);
        
        char *token = strtok(line_copy, "|");
        if (token) {
            char site[MAX_INPUT];
            strcpy(site, token);
            decrypt_string(site);
            
            if (strcmp(site, site_to_delete) == 0) {
                found = 1;
                continue;
            }
        }
        
        fprintf(fp_write, "%s", line);
    }
    
    fclose(fp_read);
    fclose(fp_write);
    
    if (found) {
        if (remove(VAULT_FILE) == 0 && rename("temp_vault.dat", VAULT_FILE) == 0) {
            printf("✓ Password deleted successfully!\n");
        } else {
            printf("Error updating vault file!\n");
        }
    } else {
        remove("temp_vault.dat");
        printf("Site not found!\n");
    }
}
