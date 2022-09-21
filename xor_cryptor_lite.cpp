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

#include "xor_cryptor_lite.h"
#include <thread>
#include <condition_variable>
#include <atomic>
#include <deque>
#include <mutex>

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

XorCryptorLite::StatusListener::~StatusListener() = default;

XorCryptorLite::byte XorCryptorLite::generate_mask(byte _v) {
    byte _mask = 0, _vt = _v;
    while (_vt) {
        _mask += (_vt & 1) == 1;
        _vt >>= 1;
    }
    _mask |= byte((8 - _mask) << 4);
    _mask = byte(_mask ^ ((_mask >> 4) | (_mask << 4)));
    return byte(_mask ^ _v);
}

void XorCryptorLite::process_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _c_len) const {
    byte64 key_idx = 0;
    for (byte64 i = 0; i < _src_len; i++) {
        if (key_idx == _c_len) key_idx = 0;
        byte _k_mask = generate_mask(_cipher[key_idx++]);
        _src[i] = byte(_src[i] ^ _k_mask);
    }
}

void XorCryptorLite::print_speed(byte64 file_size, byte64 time_end) {
    const byte64 KILO_BYTE = byte64(1024) * byte64(sizeof(unsigned char));
    const byte64 MEGA_BYTE = byte64(1024) * KILO_BYTE;

    std::string unit;
    if (file_size >= MEGA_BYTE) {
        unit = " MB/s";
        file_size /= MEGA_BYTE;
    } else {
        unit = " KB/s";
        file_size /= KILO_BYTE;
    }

    long double speed = (long double) file_size / time_end * 1000.0;
    std::stringstream str_speed;
    str_speed << std::fixed << std::setprecision(2) << speed;
    print_status("Time taken = " + std::to_string(time_end) + " [ms] - " + str_speed.str() + unit);
}

bool XorCryptorLite::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key) {
    fileManager = new FileManager(src_path, dest_path);
    if (!fileManager->is_opened()) return false;

    byte *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    byte64 file_length = std::filesystem::file_size(src_path);
    byte64 chunk_size = file_length / std::thread::hardware_concurrency();
    byte64 total_chunks = file_length / chunk_size;
    byte64 last_chunk = file_length % chunk_size;
    if (last_chunk != 0) {
        total_chunks++;
    } else {
        last_chunk = chunk_size;
    }
    fileManager->init_write_chunks(total_chunks);

    std::mutex m;
    std::condition_variable condition;
    std::atomic<byte64> thread_count = 0;

    byte **buffer_pool = new byte *[total_chunks];
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    fileManager->dispatch_writer_thread();
    for (byte64 chunk = 0; chunk < total_chunks; chunk++) {
        byte64 chunk_length = chunk == total_chunks - 1 ? last_chunk : chunk_size;
        buffer_pool[chunk] = new byte[chunk_length];
        fileManager->read_file(buffer_pool[chunk], chunk_length);

        print_status("Processing #" + std::to_string(chunk));
        std::thread([&thread_count, &condition, this]
                            (byte *_src, byte64 _s_len, byte *_cipher, byte64 _c_len, byte64 chunk_idx) -> void {
            process_bytes(_src, _s_len, _cipher, _c_len);
            if (fileManager != nullptr) {
                fileManager->write_chunk(_src, _s_len, chunk_idx);
            } else {
                print_status("File manager null #" + std::to_string(chunk_idx));
            }

            thread_count++;
            condition.notify_all();
        }, buffer_pool[chunk], chunk_length, cipher_key, key.length(), chunk).detach();
    }
    std::unique_lock<std::mutex> lock(m);
    condition.wait(lock, [&]() -> bool { return thread_count == total_chunks; });
    fileManager->wait_writer_thread();
    delete[] buffer_pool;
    bool close_res = fileManager->close_file();

    byte64 time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_speed(file_length, time_end);
    return close_res;
}

void XorCryptorLite::encrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener) {
    mStatusListener = listener;

    byte *input = new byte[str.length()], *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < str.length(); i++) input[i] = str[i];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    process_bytes(input, str.length(), cipher_key, key.length());
    for (byte64 i = 0; i < str.length(); i++) dest->push_back((char) input[i]);
    delete[] input;
    delete[] cipher_key;
}

bool XorCryptorLite::encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key);
}

void XorCryptorLite::decrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener) {
    mStatusListener = listener;

    byte *input = new byte[str.length()], *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < str.length(); i++) input[i] = str[i];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    process_bytes(input, str.length(), cipher_key, key.length());
    for (byte64 i = 0; i < str.length(); i++) dest->push_back((char) input[i]);
    delete[] input;
    delete[] cipher_key;
}

bool XorCryptorLite::decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key);
}
