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

void xorCrypt::encrypt(const std::vector<byte> &text, const std::vector<byte> &key, XORCipherData *output) {
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
        int k = 0;
        for (byte i : text) {
            if (k == key.size()) k = 0;
            int c = effolkronium::random_static::get(0, 127);
            enc.push_back((byte) (i ^ key[k] ^ c));
            enc.push_back((byte) c);
            k++;
        }
        output->data = enc;
    } catch (std::exception &e) {
        output->err = e.what();
    }
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
        std::vector<byte> rands, encrypted, decrypt;
        for (int i = 0; i < input.size(); i++) {
            if (i % 2 == 0) {
                rands.push_back(input[i]);
            } else {
                encrypted.push_back(input[i]);
            }
        }

        int k = 0, c = 0;
        for (byte i : encrypted) {
            if (k == key.size()) k = 0;
            if (c == rands.size()) c = 0;
            decrypt.push_back((byte) (i ^ key[k] ^ rands[c]));
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
