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

#include "xor_cryptor.h"

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

XorCryptor::byte XorCryptor::generate_mask(byte v) {
    byte mask = 0, vt = v;
    while (vt) {
        mask += (vt & 1) == 1;
        vt >>= 1;
    }
    mask |= byte((8 - mask) << 4);
    mask = byte(mask ^ ((mask >> 4) | (mask << 4)));
    return byte(mask ^ v);
}

void XorCryptor::generate_cipher_bytes(byte *_cipher, byte64 _k_len, byte *_table, bool to_encrypt) {
    for (byte64 i = 0; i < _k_len; i++) _cipher[i] = generate_mask(_cipher[i]);

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
        mask                          = (mask << 4) | mode;
        _table[to_encrypt ? i : mask] = to_encrypt ? mask : i;
        mask = mode = 0;
    }
}

void XorCryptor::encrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table) {
    byte64 i;
    byte   mask = 0, mode = 0;
    for (i = 0; i < _src_len; i++) {
        if (i & 1) {
            mask |= (_table[_src[i]] & 0xF0);
            mode |= ((_table[_src[i]] & 0xF) << 4);
            mode ^= mask;

            _src[i]        = byte(mode ^ _cipher[i % _k_len]);
            _src[i - 1ULL] = byte(mask ^ _cipher[(i - 1ULL) % _k_len]);
            mask = mode = 0;
        } else {
            mask |= (_table[_src[i]] >> 4);
            mode |= (_table[_src[i]] & 0xF);
        }
    }
    if (_src_len & 1) {
        mode ^= mask;
        byte value     = (mask << 4) | mode;
        _src[i - 1ULL] = byte(value ^ _cipher[(i - 1ULL) % _k_len]);
    }
}

void XorCryptor::decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table) {
    byte64 i, k = 0;
    byte64 odd = _src_len & 1;
    byte   mask, mode;
    for (i = 0; i < _src_len; i++) {
        mask = byte(_src[i] ^ _cipher[i % _k_len]);
        if (i == (_src_len - 1ULL) && odd) {
            mode = mask & 0xF;
            mask >>= 4;
            mode ^= mask;

            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
        } else {
            i++;
            mode = byte(_src[i] ^ _cipher[i % _k_len]);
            mode ^= mask;

            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
            mask >>= 4, mode >>= 4;
            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
        }
    }
}

void XorCryptor::process_data(const std::string &input_data, const std::string &key, std::string *dest, bool to_encrypt) {
    if (input_data.empty()) return;
    if (key.empty() || key.length() < 6) return;

    byte *src    = new byte[input_data.length()],
         *cipher = new byte[key.length()],
         *_table = new byte[0x100];
    for (size_t i = 0; i < input_data.length(); i++) src[i] = input_data[i];
    for (size_t i = 0; i < key.length(); i++) cipher[i] = key[i];
    generate_cipher_bytes(cipher, key.length(), _table, to_encrypt);

    if (to_encrypt) {
        encrypt_bytes(src, input_data.length(), cipher, key.length(), _table);
    } else {
        decrypt_bytes(src, input_data.length(), cipher, key.length(), _table);
    }
    for (size_t i = 0; i < input_data.length(); i++) dest->push_back((char) src[i]);

    delete[] src;
    delete[] cipher;
    delete[] _table;
}

void XorCryptor::encrypt(const std::string &input_data, const std::string &key, std::string *dest) {
    process_data(input_data, key, dest, true);
}

void XorCryptor::decrypt(const std::string &input_data, const std::string &key, std::string *dest) {
    process_data(input_data, key, dest, false);
}
