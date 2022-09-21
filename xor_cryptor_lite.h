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

#include <vector>
#include <fstream>
#include <filesystem>
#include "file_manager.h"

struct XorCryptorLite {

    typedef unsigned char byte;
    typedef uint64_t byte64;

    inline static const std::string FILE_EXTENSION = ".xrl";

    struct StatusListener {
        virtual void print_status(const std::string &status) = 0;

        virtual void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) = 0;

        virtual ~StatusListener() = 0;
    };

private:
    StatusListener *mStatusListener = nullptr;
    FileManager *fileManager = nullptr;

    static byte generate_mask(byte _v);

    void process_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _c_len) const;

    void print_status(const std::string &status) const {
        if (mStatusListener == nullptr) return;
        mStatusListener->print_status(status);
    }

    void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) const {
        if (mStatusListener == nullptr) return;
        mStatusListener->catch_progress(status, progress_ptr, total);
    }

    void print_speed(byte64 file_size, byte64 time_end);

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key);

public:
    XorCryptorLite() : mStatusListener(nullptr) {}

    void encrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener = nullptr);

    bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener = nullptr);

    void decrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener = nullptr);

    bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener = nullptr);

    ~XorCryptorLite() { delete mStatusListener; }
};

#endif //XOR_CRYPTOR_LITE_H
