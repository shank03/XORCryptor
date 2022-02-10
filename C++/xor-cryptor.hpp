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
    CipherData *encrypt(std::vector<byte> &text, const std::vector<byte> &key, bool randomized) {
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
            auto *encrypted = new std::vector<byte>();
            if (randomized) {
                for (auto &b : RANDOM_FLAG) encrypted->push_back(b);
            }

            int k = 0;
            for (auto &i : text) {
                if (k == key.size()) k = 0;
                int c = effolkronium::random_static::get(0, 127);
                encrypted->push_back(randomized ? (byte) (i ^ key[k] ^ c) : (byte) (i ^ key[k]));
                if (randomized) encrypted->push_back((byte) c);
                k++;
            }
            return new CipherData(encrypted, nullptr);
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
    CipherData *decrypt(std::vector<byte> &input, const std::vector<byte> &key) {
        if (input.empty() || key.empty()) {
            return new CipherData(nullptr, new std::string("Text or key NULL"));
        }
        if (key.size() < 6) {
            return new CipherData(nullptr, new std::string("Key length less than 6"));
        }

        try {
            size_t m_size = input.size();
            handleRandomized(&input);
            bool randomized = m_size > input.size();

            std::vector<byte> rands, *decrypt = new std::vector<byte>(), *encrypted = new std::vector<byte>();
            if (randomized) {
                for (int i = 0; i < input.size(); i++) {
                    if (i % 2 == 0) {
                        rands.push_back(input[i]);
                    } else {
                        encrypted->push_back(input[i]);
                    }
                }
            } else {
                encrypted = &input;
            }

            int k = 0, c = 0;
            for (byte &i : *encrypted) {
                if (k == key.size()) k = 0;
                if (c == rands.size()) c = 0;
                decrypt->push_back(randomized ? (byte) (i ^ key[k] ^ rands[c]) : (byte) (i ^ key[k]));
                k++, c++;
            }
            return new CipherData(decrypt, nullptr);
        } catch (std::exception &e) {
            return new CipherData(nullptr, new std::string(e.what()));
        }
    }

    static std::string getString(std::vector<byte> &data) {
        std::stringstream out;
        for (byte &b : data) out << (char) b;
        return out.str();
    }

private:
    const int RANDOM_FLAG_SIZE = 10;
    std::vector<byte> RANDOM_FLAG = {'R', 'A', 'N', 'D', 'O', 'M', 'I', 'Z', 'E', 'D'};

    void handleRandomized(std::vector<byte> *data) {
        if (data->size() < RANDOM_FLAG_SIZE) return;

        int flagCount = 0;
        for (int i = 0; i < RANDOM_FLAG_SIZE; i++) {
            if ((*data)[i] == RANDOM_FLAG[i]) flagCount++;
        }
        if (flagCount == RANDOM_FLAG_SIZE) data->erase(data->begin(), data->begin() + RANDOM_FLAG_SIZE);
    }
};
