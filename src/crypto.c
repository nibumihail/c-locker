#include "crypto.h"
#include <string.h>

uint32_t crypto_hash_password(const char *password) 
{
    
    uint32_t hash = 2166136261u;

    for(int i=0;password[i]!='\0';i++){
        
        hash ^= (uint8_t)password[i];
         hash *= 16777619u;
    }
    
    return hash;
}

// Partea 1: Key-Scheduling Algorithm (KSA)
void rc4_init(RC4_Context *ctx, const char *password)
{
    size_t key_len = strlen(password);
    
    // 1. Initializam vectorul S cu valori de la 0 la 255
    for (int i = 0; i < 256; i++) {
        ctx->S[i] = (uint8_t)i;
    }

    // 2. Amestecam vectorul S pe baza caracterelor din parola
    int j = 0;
    for (int i = 0; i < 256; i++) {
        j = (j + ctx->S[i] + (uint8_t)password[i % key_len]) % 256;
        
        uint8_t temp = ctx->S[i];
        ctx->S[i] = ctx->S[j];
        ctx->S[j] = temp;
    }

    // 3. Resetam indecșii de stare pentru momentul in care va incepe criptarea
    ctx->i = 0;
    ctx->j = 0;
}

void rc4_crypt(RC4_Context *ctx, uint8_t *buffer, size_t length) {

    for(size_t k=0; k<length;k++){
        ctx->i = (ctx->i+1) %256;
        ctx->j = (ctx->j + ctx->S[ctx->i]) % 256;

        uint8_t temp= ctx->S[ctx->i];
        ctx->S[ctx->i] = ctx->S[ctx->j];
        ctx->S[ctx->j] = temp;

        int t = (ctx->S[ctx->i] + ctx->S[ctx->j]) % 256;
        uint8_t K = ctx->S[t];

        buffer[k] ^= K;
    }
    
}