#include <stdio.h>
#include <string.h>
#include "crypto.h"

int main(int argc, char *argv[]) {
    const char *parola = "Politehnica2026";
    char mesaj[] = "Acesta este un text secret de test!";
    size_t len = strlen(mesaj);

    // 1. Testam functia ta de Hash
    uint32_t hash = crypto_hash_password(parola);
    printf("Hash-ul parolei '%s' este: 0x%08X\n", parola, hash);

    // 2. Testam Criptarea
    RC4_Context ctx_enc;
    rc4_init(&ctx_enc, parola);
    rc4_crypt(&ctx_enc, (uint8_t *)mesaj, len);

    printf("Mesaj criptat (in Hex): ");
    for (size_t i = 0; i < len; i++) {
        printf("%02X ", (uint8_t)mesaj[i]);
    }
    printf("\n");

    // 3. Testam Decriptarea (reinitializam cu aceeasi parola si rulam peste textul criptat)
    RC4_Context ctx_dec;
    rc4_init(&ctx_dec, parola);
    rc4_crypt(&ctx_dec, (uint8_t *)mesaj, len);

    printf("Mesaj decriptat: %s\n", mesaj);

    return 0;
}