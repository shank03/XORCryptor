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

#ifndef XOR_CRYPTOR_H
#define XOR_CRYPTOR_H

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>
#include <vector>

/// @brief A class to encrypt/decrypt files using XOR encryption
class XorCryptor {
    typedef unsigned char byte;
    typedef uint64_t      byte64;

private:
    /// @brief      Generates mask for the given byte
    /// @param _v   Byte to generate mask for
    /// @return     Mask for the given byte
    static byte generate_mask(byte _v);

    /// @brief              Generates table for the given key
    /// @param _cipher      Key to generate table for
    /// @param _k_len       Length of the key
    /// @param _table       Cipher table
    /// @param to_encrypt   Whether to encrypt or decrypt
    static void generate_cipher_bytes(byte *_cipher, byte64 _k_len, byte *_table, bool to_encrypt);

    /// @brief          Encrypts the buffer using the given key
    /// @param _src     Buffer to encrypt
    /// @param _len     Length of the buffer
    /// @param _cipher  Key to encrypt with
    /// @param _k_len   Length of the key
    static void encrypt_bytes(byte *_src, byte64 _len, const byte *_cipher, byte64 _k_len, const byte *_table);

    /// @brief              Decrypts the buffer using the given key
    /// @param _src         Buffer to decrypt
    /// @param _src_len     Length of the buffer
    /// @param _cipher      Key to decrypt with
    /// @param _k_len       Length of the key
    static void decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table);

    static void process_data(const std::string &input_data, const std::string &key, std::string *dest, bool to_encrypt);

public:
    /// @brief              Encrypts the data
    /// @param src_path     The source data
    /// @param key          The key to encrypt
    /// @param dest         The pointer to result
    /// @param listener     The status listener
    /// @return             true if the file is encrypted/decrypted successfully, else false
    static void encrypt(const std::string &input_data, const std::string &key, std::string *dest);

    /// @brief              Decrypts the data
    /// @param input_data   The source data
    /// @param key          The key to decrypt
    /// @param dest         The pointer to result
    /// @param listener     The status listener
    static void decrypt(const std::string &input_data, const std::string &key, std::string *dest);
};

#endif    // XOR_CRYPTOR_H
