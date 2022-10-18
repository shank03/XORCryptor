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

#include "file_manager.h"
#include "xor_cryptor_base.h"

class XorCryptor : private XorCryptor_Base {
private:
    const byte64 CHUNK_SIZE = byte64(1024 * 1024 * 64);    // 64 MB

    FileManager *fileManager = nullptr;

    byte *_table = nullptr;

    static byte generate_mask(byte _v);

    void generate_cipher_bytes(byte *_cipher, byte64 _k_len, bool to_encrypt) const;

    void encrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len) const;

    void decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len) const;

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt);

public:
    inline static const std::string FILE_EXTENSION = ".xrc";

    XorCryptor() { mStatusListener = nullptr; }

    bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) override;

    ~XorCryptor() { delete mStatusListener; }
};

#endif    // XOR_CRYPTOR_H
