/*
 * Copyright (c) 2021, Shashank Verma <shashank.verma2002@gmail.com>(shank03)
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

#include "effolkronium/random.hpp"    // Credits and Link: https://github.com/effolkronium/random
#include <sstream>
#include <vector>

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input, key and randomized generated character.
 *
 * date: 02-May-2021
 */
class XorCrypt {
public:
    /**
     * Stores the encrypted or decrypted data
     * and error.
     */
    struct CipherData {
        char const *data;
        uint64_t n;
        std::string *err;

        CipherData(char const *stream, uint64_t n, std::string *error) : data(stream), n(n), err(error) {}
    };

    static CipherData *encrypt(std::string &input_text, std::string &input_key) {
        const char *input_bytes = input_text.data(), *key_bytes = input_key.data();
        uint64_t tn = input_text.size(), kn = input_key.size();
        return encrypt_bytes(input_bytes, tn, key_bytes, kn);
    }

    static CipherData *encrypt(char const *input_bytes, uint64_t tn, char const *key_bytes, uint64_t kn) {
        return encrypt_bytes(input_bytes, tn, key_bytes, kn);
    }

    static CipherData *decrypt(std::string &input_text, std::string &input_key) {
        const char *input_bytes = input_text.data(), *key_bytes = input_key.data();
        uint64_t tn = input_text.size(), kn = input_key.size();
        return decrypt_bytes(input_bytes, tn, key_bytes, kn);
    }

    static CipherData *decrypt(char const *input_bytes, uint64_t tn, char const *key_bytes, uint64_t kn) {
        return decrypt_bytes(input_bytes, tn, key_bytes, kn);
    }

private:
    /**
     * Function that encrypts the provided text
     *
     * @param text       The input to be encrypted
     * @param key        The unique passcode for encrypting text
     *
     * @returns CipherData with appropriate result
     */
    static CipherData *encrypt_bytes(char const *text, uint64_t tn, char const *key, uint64_t kn) {
        if (text == nullptr || key == nullptr || tn == 0 || kn == 0) {
            return new CipherData(nullptr, 0, new std::string("Text or key NULL"));
        }
        if (kn > tn) {
            return new CipherData(nullptr, 0, new std::string("Key length more than input length"));
        }
        if (tn < 6 || kn < 6) {
            return new CipherData(nullptr, 0, new std::string("Text length or Key length less than 6"));
        }

        try {
            char *encrypted_bytes = new char[(tn * 2) + 1];
            for (uint64_t i = 0, k = 0, idx = 0; i < tn; i++) {
                if (k == kn) k = 0;
                char c = effolkronium::random_static::get<char>(0, 127);
                encrypted_bytes[idx++] = (text[i] ^ key[k++] ^ (char) c);
                encrypted_bytes[idx++] = c;
            }
            encrypted_bytes[tn * 2] = '\0';
            return new CipherData(encrypted_bytes, tn * 2, nullptr);
        } catch (std::exception &e) {
            return new CipherData(nullptr, 0, new std::string(e.what()));
        }
    }

    /**
     * Function that decrypts the encrypted text
     *
     * @param input    The encrypted text to be decrypted
     * @param key      The unique passcode for decrypting text
     *
     * @returns CipherData with appropriate result
     */
    static CipherData *decrypt_bytes(char const *input, uint64_t tn, char const *key, uint64_t kn) {
        if (input == nullptr || key == nullptr || tn == 0 || kn == 0) {
            return new CipherData(nullptr, 0, new std::string("Text or key NULL"));
        }
        if (kn < 6) {
            return new CipherData(nullptr, 0, new std::string("Key length less than 6"));
        }

        try {
            char *decrypted_bytes = new char[(tn / 2) + 1];
            for (int i = 0, k = 0, idx = 0; i < tn - 1; i += 2, k++) {
                if (k == kn) k = 0;
                char encrypted_byte = input[i], cipher_byte = input[i + 1];
                decrypted_bytes[idx++] = (encrypted_byte ^ key[k] ^ cipher_byte);
            }
            decrypted_bytes[tn / 2] = '\0';
            return new CipherData(decrypted_bytes, tn / 2, nullptr);
        } catch (std::exception &e) {
            return new CipherData(nullptr, 0, new std::string(e.what()));
        }
    }
};
