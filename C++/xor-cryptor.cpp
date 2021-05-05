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

#include <iostream>
#include <sstream>
#include <random>
#include "effolkronium/random.hpp" // Credits and Link: https://github.com/effolkronium/random
#include "xor-cryptor.h"

/**
 * XORCryptor Implementation
 *
 * date: 02-May-2021
 */

const char ALPHABETS[] = {'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
                          'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

int getRandChar() {
    char c = ALPHABETS[effolkronium::random_static::get(0, 25)];
    int cap = effolkronium::random_static::get(0, 1);
    return cap == 1 ? c - 32 : c;
}

void xorCrypt::encrypt(const std::string &text, const std::string &key, std::string *output) {
    output[0] = NULL_STR, output[1] = NULL_STR;
    if (text.empty() || key.empty()) {
        output[1] = "Text or key NULL";
        return;
    }
    if (key.length() > text.length()) {
        output[1] = "Key length more than input length";
        return;
    }
    if (text.length() < 6 || key.length() < 6) {
        output[1] = "Text length or Key length less than 6";
        return;
    }
    try {
        std::stringstream enc;
        int k = 0;
        for (char i : text) {
            if (k == key.length()) k = 0;
            int c = getRandChar();
            enc << (char) ((int) i ^ (int) key[k] ^ c) << (char) c;
            k++;
        }
        output[0] = enc.str();
    } catch (std::exception &e) {
        output[1] = e.what();
    }
}

void xorCrypt::decrypt(const std::string &input, const std::string &key, std::string *output) {
    output[0] = NULL_STR, output[1] = NULL_STR;
    if (input.empty() || key.empty()) {
        output[1] = "Text or key NULL";
        return;
    }
    if (key.length() < 6) {
        output[1] = "Key length less than 6";
        return;
    }
    try {
        std::stringstream rs, enc, decrypt;
        for (int i = 0; i < input.length(); i++) {
            if (i % 2 == 0) {
                rs << input[i];
            } else {
                enc << input[i];
            }
        }

        std::string rands = rs.str(), encrypted = enc.str();
        int k = 0, c = 0;
        for (char i : encrypted) {
            if (k == key.length()) k = 0;
            if (c == rands.length()) c = 0;
            decrypt << (char) ((int) i ^ (int) key[k] ^ (int) rands[c]);
            k++, c++;
        }
        output[0] = decrypt.str();
    } catch (std::exception &e) {
        output[1] = e.what();
    }
}
