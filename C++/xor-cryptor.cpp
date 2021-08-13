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

#include <sstream>
#include <vector>
#include "effolkronium/random.hpp" // Credits and Link: https://github.com/effolkronium/random
#include "xor-cryptor.h"

/**
 * XORCryptor Implementation
 *
 * date: 02-May-2021
 */

const int RANDOM_FLAG_SIZE = 10;
xorCrypt::byte RANDOM_FLAG[RANDOM_FLAG_SIZE] = {'R', 'A', 'N', 'D', 'O', 'M', 'I', 'Z', 'E', 'D'};

void xorCrypt::encrypt(const std::vector<byte> &text, const std::vector<byte> &key, bool randomized, XORCipherData *output) {
    output->err = NULL_STR;
    if (text.empty() || key.empty()) {
        output->err = "Text or key NULL";
        return;
    }
    if (key.size() > text.size()) {
        output->err = "Key length more than input length";
        return;
    }
    if (text.size() < 6 || key.size() < 6) {
        output->err = "Text length or Key length less than 6";
        return;
    }
    try {
        std::vector<byte> enc;
        if (randomized) {
            for (byte b : RANDOM_FLAG) enc.push_back(b);
        }
        int k = 0;
        for (byte i : text) {
            if (k == key.size()) k = 0;
            int c = effolkronium::random_static::get(0, 127);
            enc.push_back(randomized ? (byte) (i ^ key[k] ^ c) : (byte) (i ^ key[k]));
            if (randomized) enc.push_back((byte) c);
            k++;
        }
        output->data = enc;
    } catch (std::exception &e) {
        output->err = e.what();
    }
}

void handleRandomized(std::vector<xorCrypt::byte> *data) {
    if (data->size() < RANDOM_FLAG_SIZE) return;

    int flagCount = 0;
    for (int i = 0; i < RANDOM_FLAG_SIZE; i++) {
        if ((*data)[i] == RANDOM_FLAG[i]) flagCount++;
    }
    if (flagCount == RANDOM_FLAG_SIZE) data->erase(data->begin(), data->begin() + RANDOM_FLAG_SIZE);
}

void xorCrypt::decrypt(const std::vector<byte> &input, const std::vector<byte> &key, XORCipherData *output) {
    output->err = NULL_STR;
    if (input.empty() || key.empty()) {
        output->err = "Text or key NULL";
        return;
    }
    if (key.size() < 6) {
        output->err = "Key length less than 6";
        return;
    }
    try {
        std::vector<byte> fInput(input.begin(), input.end());
        handleRandomized(&fInput);
        bool randomized = fInput.size() < input.size();

        std::vector<byte> rands, encrypted, decrypt;
        if (randomized) {
            for (int i = 0; i < fInput.size(); i++) {
                if (i % 2 == 0) {
                    rands.push_back(fInput[i]);
                } else {
                    encrypted.push_back(fInput[i]);
                }
            }
        } else {
            encrypted = fInput;
        }

        int k = 0, c = 0;
        for (byte i : encrypted) {
            if (k == key.size()) k = 0;
            if (c == rands.size()) c = 0;
            decrypt.push_back(randomized ? (byte) (i ^ key[k] ^ rands[c]) : (byte) (i ^ key[k]));
            k++, c++;
        }
        output->data = decrypt;
    } catch (std::exception &e) {
        output->err = e.what();
    }
}

std::string xorCrypt::getString(const std::vector<byte> &data) {
    std::stringstream out;
    for (byte b : data) {
        out << (char) b;
    }
    return out.str();
}
