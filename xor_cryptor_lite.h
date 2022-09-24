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

#ifndef XOR_CRYPTOR_LITE_H
#define XOR_CRYPTOR_LITE_H

#include "file_manager.h"

class XorCryptorLite : private XorCryptor_Base {
private:
    FileManager *fileManager = nullptr;

    static byte generate_mask(byte _v);

    static void process_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _c_len);

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key);

public:
    inline static const std::string FILE_EXTENSION = ".xrl";

    XorCryptorLite() { mStatusListener = nullptr; }

    void encrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener = nullptr);

    bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    void decrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener = nullptr);

    bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    ~XorCryptorLite() { delete mStatusListener; }
};

#endif    // XOR_CRYPTOR_LITE_H
