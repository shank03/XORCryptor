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

#pragma once

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input, key and randomized generated character.
 *
 * date: 02-May-2021
 */
namespace xorCrypt {

#define NULL_STR "!#-"

    typedef unsigned char byte;

    typedef struct cipher {
        std::vector<byte> data;
        std::string err;
    } XORCipherData;

    /**
     * Function that encrypts the provided text
     *
     * @param text     The input to be encrypted
     * @param key      The unique passcode for encrypting/decrypting text
     * @param output   The pointer of array (whose length should be 2). The data is passed
     *                 through this array where [0] is encrypted data and [1] is error if any occurred
     */
    void encrypt(const std::vector<byte> &text, const std::vector<byte> &key, XORCipherData *output);

    /**
     * Function that decrypts the encrypted text
     *
     * @param input    The encrypted text to be decrypted
     * @param key      The unique passcode for encrypting/decrypting text
     * @param output   The pointer of array (whose length should be 2). The data is passed
     *                 through this array where [0] is decrypted data and [1] is error if any occurred
     */
    void decrypt(const std::vector<byte> &input, const std::vector<byte> &key, XORCipherData *output);

    std::string getString(const std::vector<byte> &data);
}
