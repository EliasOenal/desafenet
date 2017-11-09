/* desafenet
 * A cross platform utility to handle E-SafeNet
 * protected files.
 *
 * Written and placed into the public domain by
 * Elias Oenal <desafenet@eliasoenal.com>
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

#include "minilzo.h"

#define APPNAME "desafenet"
#define ESAFE_BLOCK 512

enum{
    ESAFE_COMP_MODE_LZO = 0x62, // Data compressed using LZO
    ESAFE_COMP_MODE_PSUB = 0x63 // Unknown pattern substitution algorithm
};

typedef struct safe_info{
    bool is_esafe;
    uint8_t mode;
    uint16_t offset;
} safe_info;

safe_info verify_esafe_header(FILE* file);
bool recover_key(FILE* plaintext, FILE* ciphertext, uint8_t* key);
void esafe_crypt(uint8_t* data, const uint8_t* key, uint16_t len);
bool esafe_decompress(uint8_t* data, uint16_t size);
const char *esafe_mode_to_str(uint8_t mode);

static unsigned int verbosity = 0;

int main(int argc, char *argv[])
{
    const char* keyfile_str = NULL;
    const char* plaintext_str = NULL;
    const char* ciphertext_str = NULL;
    FILE* keyfile = NULL;
    FILE* plaintext = NULL;
    FILE* ciphertext = NULL;

    int opt;
    while((opt = getopt(argc, argv, "k:p:c:v")) != -1)
    {
        switch(opt)
        {
        case 'k':
            keyfile_str = optarg;
            keyfile = fopen(keyfile_str, "rb");
            if(!keyfile_str || !keyfile)
                goto err_abort;
            break;

        case 'p':
            plaintext_str = optarg;
            plaintext = fopen(plaintext_str, "rb");
            if(!plaintext_str || !plaintext)
                goto err_abort;
            break;

        case 'c':
            ciphertext_str = optarg;
            ciphertext = fopen(ciphertext_str, "rb");
            if(!ciphertext_str || !ciphertext)
                goto err_abort;
            break;

        case 'v':
            verbosity = 1;
            break;
        }
    }

    safe_info info_cipher = {info_cipher.is_esafe = false, info_cipher.mode = 0, info_cipher.offset = 0};
    if(ciphertext)
    {
        info_cipher = verify_esafe_header(ciphertext);
        if(!info_cipher.is_esafe)
        {
            fprintf(stderr, "%s: %s: ciphertext either unencrypted or unsupported\n", APPNAME, ciphertext_str);
            goto err_abort;
        }
        else if(verbosity > 0)
            fprintf(stderr, "%s: %s: compression mode %s and data offset %u\n", APPNAME, ciphertext_str,
                    esafe_mode_to_str(info_cipher.mode), info_cipher.offset);
    }

    if(plaintext)
    {
        if(verify_esafe_header(plaintext).is_esafe)
        {
            fprintf(stderr, "%s: %s: plaintext input seems to be encrypted\n", APPNAME, plaintext_str);
            goto err_abort;
        }
    }

    if((keyfile?1:0) + (plaintext?1:0) + (ciphertext?1:0) != 2)
    {
        fprintf(stderr, "%s: two out of -k (key) -p (plaintext) and -c (ciphertext) required\n", APPNAME);
        return 1;
    }

    if(plaintext && ciphertext)
    {
        uint8_t key[ESAFE_BLOCK];
        bool success = recover_key(plaintext, ciphertext, key);
        if(!success)
        {
            fprintf(stderr, "%s: failed to recover or verify key, try files of at least 1.5kb\n", APPNAME);
            goto err_abort;
        }

        if(verbosity > 0)
            fprintf(stderr, "%s: recovered and verified key\n", APPNAME);

        fwrite(key, sizeof(uint8_t), sizeof(key), stdout);
    }
    else if(ciphertext && keyfile)
    {
        uint8_t key[ESAFE_BLOCK];
        uint8_t data[ESAFE_BLOCK];
        size_t read;

        fseek(keyfile, 0, SEEK_SET);
        if(fread(key, 1, ESAFE_BLOCK, keyfile) != sizeof(key))
        {
            fprintf(stderr, "%s: %s: invalid keyfile\n", APPNAME, keyfile_str);
            goto err_abort;
        }

        fseek(ciphertext, info_cipher.offset, SEEK_SET);
        read = fread(data, 1, sizeof(data) - info_cipher.offset, ciphertext);
        esafe_crypt(data, key, read);

        switch(info_cipher.mode)
        {
        case ESAFE_COMP_MODE_LZO:
        {
            bool status = esafe_decompress(data, read);
            if(!status)
            {
                fprintf(stderr, "%s: error decompressing the data\n", APPNAME);
                fwrite(data, sizeof(uint8_t), read, stdout);
                goto err_abort;
            }
            fwrite(data, sizeof(uint8_t), ESAFE_BLOCK, stdout);
            break;
        }

        case ESAFE_COMP_MODE_PSUB:
            // Sadly we don't have the dictionary used for PSUB
        default:
        {
            fprintf(stderr, "%s: %s: compression mode %s is unsupported for decompression, "
                            "dumping first block compressed and prefixed with 0x00\n", APPNAME, ciphertext_str,
                            esafe_mode_to_str(info_cipher.mode));

            for(size_t i = 0; i < info_cipher.offset; i++)
                fwrite("\0", 1, 1, stdout); // Padding
            fwrite(data, sizeof(uint8_t), read, stdout);
            break;
        }
        }


        fseek(ciphertext, ESAFE_BLOCK * 1, SEEK_SET);
        while(true)
        {
            read = fread(data, 1, sizeof(data), ciphertext);

            esafe_crypt(data, key, read);

            fwrite(data, sizeof(uint8_t), read, stdout);

            if(!read || feof(ciphertext))
                break;
        }
    }
    else if(plaintext && keyfile)
    {
        fprintf(stderr, "%s: encryption currently unsupported\n", APPNAME);
        goto err_abort;
    }

    return 0;


err_abort:
    if(keyfile)
        fclose(keyfile);
    if(plaintext)
        fclose(plaintext);
    if(ciphertext)
        fclose(ciphertext);

    return 1;
}

void esafe_crypt(uint8_t* data, const uint8_t* key, uint16_t len)
{
    for(size_t i = 0; i < len; i++)
        data[i] ^= key[i];
}

bool esafe_decompress(uint8_t* data, uint16_t size)
{
    lzo_uint out_len = ESAFE_BLOCK;
    uint8_t buff[ESAFE_BLOCK] = {0};
    int res = lzo1x_decompress_safe(data, size, buff, &out_len, NULL);

    if(verbosity > 1)
        fprintf(stderr, "res: %d siz: %d\n", res, size);

    if(res != LZO_E_OK)
        return false;

    memcpy(data, buff, sizeof(buff));
    return true;
}

bool recover_key(FILE* plaintext, FILE* ciphertext, uint8_t* key)
{
    fseek(plaintext, ESAFE_BLOCK, SEEK_SET);
    fseek(ciphertext, ESAFE_BLOCK, SEEK_SET);
    uint8_t pt_chunk;
    uint8_t ct_chunk;

    // Recover key
    for(int i = 0; i < ESAFE_BLOCK; i++)
    {
        if(fread(&pt_chunk, sizeof(uint8_t), 1, plaintext) != sizeof(uint8_t) ||
                fread(&ct_chunk, sizeof(uint8_t), 1, ciphertext) != sizeof(uint8_t))
            return false;
        key[i] = pt_chunk ^ ct_chunk;
    }

    // Try to verify key
    for(int i = 0; i < ESAFE_BLOCK; i++)
    {
        if(fread(&pt_chunk, sizeof(uint8_t), 1, plaintext) != sizeof(uint8_t) ||
                fread(&ct_chunk, sizeof(uint8_t), 1, ciphertext) != sizeof(uint8_t))
            return false;
        if(key[i] != (pt_chunk ^ ct_chunk))
            return false;
    }

    return true;
}

#define ESAFE_HDR 17
safe_info verify_esafe_header(FILE* file)
{
    const uint8_t magic_string1[] = {0x14, 0x23, 0x65};
    const uint8_t magic_string2[] = {0x01};

    uint8_t buff[17] = {0};
    safe_info info = {info.is_esafe = false, info.mode = 0, info.offset = 0};

    if(!file)
        return info;

    fseek(file, 0, SEEK_SET);
    size_t read = fread(buff, 1, ESAFE_HDR, file);
    if(read != ESAFE_HDR)
        goto err_abort;

    if(!memcmp(&buff[1], magic_string1, sizeof(magic_string1)) &&
            !memcmp(&buff[11], magic_string2, sizeof(magic_string2)))
    {
        info.is_esafe = true;
        info.mode = buff[0];
        info.offset = (buff[5] << 8) | buff[4];
    }

err_abort:
    return info;
}

const char* esafe_mode_to_str(uint8_t mode)
{
    const char* lzo_str = "LZO";
    const char* psub_str = "PSUB";
    static char unknown_str[20];

    switch(mode)
    {
    case ESAFE_COMP_MODE_LZO:
        return lzo_str;
    case ESAFE_COMP_MODE_PSUB:
        return psub_str;
    default:
        sprintf(unknown_str, "unknown_0x%02X", mode);
        return unknown_str;
    }
}
