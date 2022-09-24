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

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

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

void XorCryptorLite::process_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _c_len) {
    byte *masks = new byte[_c_len];
    for (byte64 i = 0; i < _c_len; i++) masks[i] = generate_mask(_cipher[i]);

    for (byte64 i = 0; i < _src_len; i++) _src[i] = byte(_src[i] ^ masks[i % _c_len]);
    delete[] masks;
}

bool XorCryptorLite::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key) {
    fileManager = new FileManager(src_path, dest_path);
    if (!fileManager->is_opened()) return false;

    byte *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    byte64 file_length  = std::filesystem::file_size(src_path);
    byte64 chunk_size   = file_length / byte64(std::thread::hardware_concurrency() - 2);
    byte64 total_chunks = file_length / chunk_size;
    byte64 last_chunk   = file_length % chunk_size;
    if (last_chunk != 0) {
        total_chunks++;
    } else {
        last_chunk = chunk_size;
    }
    fileManager->init_write_chunks(total_chunks);

    std::mutex              m;
    std::atomic<byte64>     thread_count = 0;
    std::atomic<byte64>     duration     = 0;
    std::condition_variable condition;

    fileManager->dispatch_writer_thread(mStatusListener);

    byte64 chunk = 0;
    auto   begin = std::chrono::steady_clock::now();
    for (; chunk < total_chunks; chunk++) {
        catch_progress("Processing chunks", &chunk, total_chunks);
        byte64 chunk_length = chunk == total_chunks - 1 ? last_chunk : chunk_size;
        byte  *buffer       = new byte[chunk_length];

        auto read_beg = std::chrono::steady_clock::now();
        fileManager->read_file(buffer, chunk_length);
        byte64 read_time = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_beg).count();

        std::thread(
                [&thread_count, &condition, &duration, &begin, this](byte *_src, byte64 _s_len, byte *_cipher, byte64 _c_len, byte64 chunk_idx, byte64 read_time) -> void {
                    process_bytes(_src, _s_len, _cipher, _c_len);
                    byte64 curr = duration;
                    byte64 end  = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count() - read_time;
                    duration    = std::max(curr, end);

                    if (fileManager != nullptr) {
                        fileManager->write_chunk(_src, _s_len, chunk_idx);
                    } else {
                        print_status("File manager null #" + std::to_string(chunk_idx));
                    }

                    thread_count++;
                    condition.notify_all();
                },
                buffer, chunk_length, cipher_key, key.length(), chunk, read_time)
                .detach();
    }
    std::unique_lock<std::mutex> lock(m);
    condition.wait(lock, [&]() -> bool { return thread_count == total_chunks; });
    print_speed(file_length, duration);

    catch_progress("Writing file", nullptr, 0);
    fileManager->wait_writer_thread();
    return fileManager->close_file();
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
