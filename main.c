#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "encrypt.h"
#include "file_ops.h"

int main() {
    char master[256];
    
    printf(" PASSWORD VAULT \n");
    
    
    if (!verify_master(master)) {
        printf("\nAccess denied. Vault locked.\n");
        return 0;
    }
    
    printf("\nAccess granted!\n");
    
    init_crypto(master);
    
    memset(master, 0, sizeof(master));
    
    int choice;
    do {
     
        printf("           PASSWORD VAULT                  \n");
        printf("===========================================\n");
        printf("  1 - Add new password                     \n");
        printf("  2 - View saved passwords                 \n");
        printf("  3 - Delete password                      \n");
        printf("  4 - Exit                                 \n");
       
        printf("\nChoice: ");
        
        if (scanf("%d", &choice) != 1) {
            while (getchar() != '\n');
            printf("Invalid input! Please enter a number.\n");
            continue;
        }
        while (getchar() != '\n');
        
        switch (choice) {
        case 1:
            printf("\n>>> ADD NEW PASSWORD\n");
            add_password();
            break;
        case 2:
            printf("\n>>> VIEW PASSWORDS\n");
            view_passwords();
            printf("Press Enter to continue...");
            getchar();
            break;
        case 3:
            printf("\n>>> DELETE PASSWORD\n");
            delete_password();
            break;
        case 4:
            printf("\nVault locked. Goodbye!\n");
            break;
        default:
            printf("\nInvalid option. Choose 1-4.\n");
        }
        
    } while (choice != 4);
    
    return 0;
}
