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

XorCryptorLite::StatusListener::~StatusListener() = default;

XorCryptorLite::byte XorCryptorLite::generate_mask(byte _v) {
    byte _mask = 0, _vt = _v;
    while (_vt) {
        _mask += (_vt & 1) == 1;
        _vt >>= 1;
    }
    _mask |= byte((8 - _mask) << 4);
    _mask = byte(_mask ^ ((_mask >> 4) | (_mask << 4)));
//    _mask = byte(_mask ^ ((_v >> 4) | (_v << 4)));
    return byte(_mask ^ _v);
}

void XorCryptorLite::process_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _c_len, byte64 *itr) const {
    byte64 key_idx = 0;
    catch_progress("Processing bytes", itr, _src_len);
    for (; *itr < _src_len; (*itr)++) {
        if (key_idx == _c_len) key_idx = 0;
        byte _k_mask = generate_mask(_cipher[key_idx++]);
        _src[*itr] = byte(_src[*itr] ^ _k_mask);
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
    std::fstream file(src_path, std::ios::in | std::ios::binary);
    std::fstream output_file(dest_path, std::ios::out | std::ios::binary);
    if (!file.is_open()) return false;
    if (!output_file.is_open()) return false;

    catch_progress("Reading file", nullptr, 0);
    file.seekg(0, std::ios::end);
    auto input_length = file.tellg();
    byte *input = new byte[input_length];

    file.seekg(0, std::ios::beg);
    file.read((char *) input, input_length);
    file.close();

    print_status("File size: " + std::to_string(input_length) + " bytes");

    byte *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();
    byte64 itr = 0;
    process_bytes(input, input_length, cipher_key, key.length(), &itr);
    byte64 time_end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_speed(input_length, time_end);

    catch_progress("Writing file", nullptr, 0);
    output_file.write((char *) input, std::streamsize(input_length));
    output_file.close();
    delete[] input;
    return !file.is_open() && !output_file.is_open();
}

void XorCryptorLite::encrypt_string(const std::string &str, const std::string &key, std::string *dest, StatusListener *listener) {
    mStatusListener = listener;

    byte *input = new byte[str.length()], *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < str.length(); i++) input[i] = str[i];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    byte64 itr = 0;
    process_bytes(input, str.length(), cipher_key, key.length(), &itr);
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

    byte64 itr = 0;
    process_bytes(input, str.length(), cipher_key, key.length(), &itr);
    for (byte64 i = 0; i < str.length(); i++) dest->push_back((char) input[i]);
    delete[] input;
    delete[] cipher_key;
}

bool XorCryptorLite::decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key);
}
