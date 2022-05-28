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

#include "effolkronium/random.hpp"// Credits and Link: https://github.com/effolkronium/random
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
    typedef unsigned char byte;

    /**
     * Stores the encrypted or decrypted data
     * and error.
     */
    struct CipherData {
        std::vector<byte> *data;
        std::string *err;

        CipherData(std::vector<byte> *stream, std::string *error) : data(stream), err(error) {}
    };

    /**
     * Function that encrypts the provided text
     *
     * @param text       The input to be encrypted
     * @param key        The unique passcode for encrypting/decrypting text
     * @param randomized Whether to randomize encryption
     * 
     * @returns CipherData with appropriate result
     *
     * @note Enabling randomization will return you double the size of original data
     */
    static CipherData *encrypt(std::vector<byte> &text, const std::vector<byte> &key) {
        if (text.empty() || key.empty()) {
            return new CipherData(nullptr, new std::string("Text or key NULL"));
        }
        if (key.size() > text.size()) {
            return new CipherData(nullptr, new std::string("Key length more than input length"));
        }
        if (text.size() < 6 || key.size() < 6) {
            return new CipherData(nullptr, new std::string("Text length or Key length less than 6"));
        }

        try {
            auto *encrypted_bytes = new std::vector<byte>();

            int k = 0;
            for (auto &i : text) {
                if (k == key.size()) k = 0;
                int c = effolkronium::random_static::get(0, 127);
                encrypted_bytes->push_back((byte) (i ^ key[k] ^ c));
                encrypted_bytes->push_back((byte) (key[k] ^ c));
                k++;
            }
            return new CipherData(encrypted_bytes, nullptr);
        } catch (std::exception &e) {
            return new CipherData(nullptr, new std::string(e.what()));
        }
    }

    /**
     * Function that decrypts the encrypted text
     *
     * @param input    The encrypted text to be decrypted
     * @param key      The unique passcode for encrypting/decrypting text
     *
     * @returns CipherData with appropriate result
     */
    static CipherData *decrypt(std::vector<byte> &input, const std::vector<byte> &key) {
        if (input.empty() || key.empty()) {
            return new CipherData(nullptr, new std::string("Text or key NULL"));
        }
        if (key.size() < 6) {
            return new CipherData(nullptr, new std::string("Key length less than 6"));
        }

        try {
            auto *decrypted_bytes = new std::vector<byte>();
            for (int i = 0, k = 0; i < input.size() - 1; i += 2, k++) {
                if (k == key.size()) k = 0;
                byte encrypted_byte = input[i], cipher_byte = input[i + 1];
                cipher_byte = (cipher_byte ^ key[k]);
                decrypted_bytes->push_back((byte) (encrypted_byte ^ key[k] ^ cipher_byte));
            }
            return new CipherData(decrypted_bytes, nullptr);
        } catch (std::exception &e) {
            return new CipherData(nullptr, new std::string(e.what()));
        }
    }

    static std::string getString(std::vector<byte> &data) {
        std::stringstream out;
        for (byte &b : data) out << (char) b;
        return out.str();
    }
};
