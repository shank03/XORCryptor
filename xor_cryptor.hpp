/*
 * Copyright (c) 2022, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 */

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

#ifndef XOR_CRYPTOR_HPP
#define XOR_CRYPTOR_HPP

/// @brief A class to encrypt/decrypt files using XOR encryption
class XorCryptor {
    typedef unsigned char      byte;
    typedef unsigned long long byte64;

public:
    enum Mode { ENCRYPT,
                DECRYPT,
                INVALID };

private:
    byte *p_cipher,
            *pe_table, *pd_table;
    byte64 l_cipher;

    static byte generate_mask(byte v) {
        byte mask = 0, vt = v;
        while (vt) {
            mask += (vt & 1) == 1;
            vt >>= 1;
        }
        mask |= byte((8 - mask) << 4);
        mask = byte(mask ^ ((mask >> 4) | (mask << 4)));
        return byte(mask ^ v);
    }

    void generate_cipher_table() {
        byte mask = 0, mode = 0, count, shift, value, bit_mask;
        for (int i = 0; i <= 255; i++) {
            count = 4, shift = 0, value = i;
            while (count--) {
                bit_mask = value & 3;
                if (bit_mask > 1) mask |= (1 << shift);
                if (bit_mask == 0 || bit_mask == 3) mode |= (1 << shift);
                shift++;
                value >>= 2;
            }
            mask = (mask << 4) | mode;

            pe_table[i]    = mask;
            pd_table[mask] = i;
            mask = mode = 0;
        }
    }

public:
    XorCryptor(const byte *key, byte64 l_key) {
        if (l_key < 6) return;

        l_cipher = l_key;
        p_cipher = new byte[l_cipher];
        for (byte64 i = 0; i < l_cipher; i++) p_cipher[i] = generate_mask(key[i]);

        pe_table = new byte[0x100], pd_table = new byte[0x100];
        generate_cipher_table();
    }

    [[nodiscard]] byte *get_cipher() const { return p_cipher; }

    void encrypt_bytes(byte *src, byte64 src_len) {
        byte64 i;
        byte   mask = 0, mode = 0;
        for (i = 0; i < src_len; i++) {
            if (i & 1) {
                mask |= (pe_table[src[i]] & 0xF0);
                mode |= ((pe_table[src[i]] & 0xF) << 4);
                mode ^= mask;

                src[i]        = byte(mode ^ p_cipher[i % l_cipher]);
                src[i - 1ULL] = byte(mask ^ p_cipher[(i - 1ULL) % l_cipher]);
                mask = mode = 0;
            } else {
                mask |= (pe_table[src[i]] >> 4);
                mode |= (pe_table[src[i]] & 0xF);
            }
        }
        if (src_len & 1) {
            mode ^= mask;
            byte value    = (mask << 4) | mode;
            src[i - 1ULL] = byte(value ^ p_cipher[(i - 1ULL) % l_cipher]);
        }
    }

    void decrypt_bytes(byte *src, byte64 src_len) {
        byte64 i, k = 0;
        byte64 odd = src_len & 1;
        byte   mask, mode;
        for (i = 0; i < src_len; i++) {
            mask = byte(src[i] ^ p_cipher[i % l_cipher]);
            if (i == (src_len - 1ULL) && odd) {
                mode = mask & 0xF;
                mask >>= 4;
                mode ^= mask;
            } else {
                i++;
                mode = byte(src[i] ^ p_cipher[i % l_cipher]);
                mode ^= mask;

                src[k++] = pd_table[((mask & 0xF) << 4) | (mode & 0xF)];
                mask >>= 4, mode >>= 4;
            }
            src[k++] = pd_table[((mask & 0xF) << 4) | (mode & 0xF)];
        }
    }

    ~XorCryptor() {
        for (byte64 i = 0; i < l_cipher; i++) p_cipher[i] = 0;
        delete[] p_cipher;

        for (byte64 i = 0; i < 0x100; i++) pe_table[i] = 0;
        delete[] pe_table;
    }
};

#endif    // XOR_CRYPTOR_HPP
