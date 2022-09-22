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

#ifndef XOR_CRYPTOR_BASE_H
#define XOR_CRYPTOR_BASE_H

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <thread>
#include <vector>

class XorCryptor_Base {
public:
    typedef unsigned char     byte;
    typedef uint64_t          byte64;
    typedef std::vector<byte> ByteStream;

    struct StatusListener {
        virtual void print_status(const std::string &status) = 0;

        virtual void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) = 0;

        virtual ~StatusListener() = 0;
    };

protected:
    StatusListener *mStatusListener = nullptr;

    void print_status(const std::string &status) const;

    void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) const;

    void print_speed(byte64 fileSize, byte64 time_end);

    ~XorCryptor_Base() { delete mStatusListener; }

public:
    virtual bool encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) = 0;

    virtual bool decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) = 0;
};

#endif    // XOR_CRYPTOR_BASE_H
