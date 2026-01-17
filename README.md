# Password Manager in C

A secure password manager written in C with AES-256-GCM encryption.

## Features

- Add new passwords with site name and username
- View all saved passwords with decryption
- Delete passwords by site name
- Master password protection with PBKDF2
- AES-256-GCM encryption for all data
- Random salt generation for password hashing
- Memory cleanup to prevent data leakage

## Security

- AES-256-GCM encryption (military-grade)
- PBKDF2 key derivation with 100,000 iterations
- Random salt for each installation
- All metadata (site, username, password) encrypted
- Authentication tags for data integrity verification
- Secure memory cleanup after operations

## Prerequisites

- GCC compiler
- OpenSSL library (libssl-dev)
- Linux or macOS (Windows with MinGW)

## Installation

Clone the repository:
```
git clone https://github.com/val3yne/password-manager.git
cd password-manager
```

Compile the program:
```
gcc -o vault main.c encrypt.c file_ops.c -lssl -lcrypto -Wall
```

## Usage

Run the program:
```
./vault
```

On first run, create a password (minimum 8 characters).

## Technical Details

**Encryption Algorithm:** AES-256-GCM

**Key Derivation:** PBKDF2-HMAC-SHA256 with 100,000 iterations


## Security Notes

- All data (site, username, password) is encrypted
- Master password is hashed and never stored in plain text
- Random salt prevents rainbow table attacks
- Authentication tags detect data tampering
- Memory is securely wiped after sensitive operations

## Important

- Do not share passwords.dat without the salt file
- Losing master password means losing all data




