#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stddef.h>

// Structura care pastreaza starea interna a cifrului RC4.
// Avem nevoie de ea pentru ca vom citi fisierele in bucati de 4KB,
// iar cifrul trebuie sa tina minte unde a ramas intre doua citiri.
typedef struct {
    uint8_t S[256]; // Vectorul de permutari (256 de octeti)
    int i;          // Indexul 1
    int j;          // Indexul 2
} RC4_Context;

// 1. Calculeaza amprenta (Hash FNV-1a pe 32 de biti) a parolei
uint32_t crypto_hash_password(const char *password);

// 2. Initializeaza vectorul S[256] pe baza parolei (Key-Scheduling Algorithm)
void rc4_init(RC4_Context *ctx, const char *password);

// 3. Cripteaza sau decripteaza un bloc de memorie (PRGA)
void rc4_crypt(RC4_Context *ctx, uint8_t *buffer, size_t length);

#endif