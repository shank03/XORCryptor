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

#include "xor_cryptor.h"

/**
 * XORCryptor
 * <p>
 * Encrypts input text using XOR operation with individual characters
 * from input and key character.
 *
 * date: 21-Sep-2022
 */

XorCryptor::StatusListener::~StatusListener() = default;

XorCryptor::byte XorCryptor::generate_mask(byte v) {
    byte mask = 0, vt = v;
    while (vt) {
        mask += (vt & 1) == 1;
        vt >>= 1;
    }
    mask |= byte((8 - mask) << 4);
    mask = byte(mask ^ ((mask >> 4) | (mask << 4)));
    return byte(mask ^ v);
}

void XorCryptor::generate_cipher_bytes(byte *_cipher, byte64 _k_len, byte *_table, const XrcMode &xrc_mode) {
    for (byte64 i = 0; i < _k_len; i++) _cipher[i] = generate_mask(_cipher[i]);

    byte mask = 0, mode = 0, count, shift, value, bit_mask;
    for (int i = 0; i <= 255; i++) {
        count = 4, shift = 0, value = i;
        while (count--) {
            bit_mask = value & 3;
            if (bit_mask > 1) mask |= (1 << shift);
            if (bit_mask == 0 || bit_mask == 3) mode |= (1 << shift);
            shift++;
            value >>= 2;
        }
        mask = (mask << 4) | mode;

        _table[xrc_mode == XrcMode::ENCRYPT ? i : mask] = xrc_mode == XrcMode::ENCRYPT ? mask : i;
        mask = mode = 0;
    }
}

void XorCryptor::encrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table) {
    byte64 i;
    byte   mask = 0, mode = 0;
    for (i = 0; i < _src_len; i++) {
        if (i & 1) {
            mask |= (_table[_src[i]] & 0xF0);
            mode |= ((_table[_src[i]] & 0xF) << 4);
            mode ^= mask;

            _src[i]        = byte(mode ^ _cipher[i % _k_len]);
            _src[i - 1ULL] = byte(mask ^ _cipher[(i - 1ULL) % _k_len]);
            mask = mode = 0;
        } else {
            mask |= (_table[_src[i]] >> 4);
            mode |= (_table[_src[i]] & 0xF);
        }
    }
    if (_src_len & 1) {
        mode ^= mask;
        byte value     = (mask << 4) | mode;
        _src[i - 1ULL] = byte(value ^ _cipher[(i - 1ULL) % _k_len]);
    }
}

void XorCryptor::decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table) {
    byte64 i, k = 0;
    byte64 odd = _src_len & 1;
    byte   mask, mode;
    for (i = 0; i < _src_len; i++) {
        mask = byte(_src[i] ^ _cipher[i % _k_len]);
        if (i == (_src_len - 1ULL) && odd) {
            mode = mask & 0xF;
            mask >>= 4;
            mode ^= mask;
        } else {
            i++;
            mode = byte(_src[i] ^ _cipher[i % _k_len]);
            mode ^= mask;

            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
            mask >>= 4, mode >>= 4;
        }
        _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
    }
}

bool XorCryptor::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key,
                              ThreadPool *thread_pool, const XrcMode &mode, bool preserve_src) {
    auto *file_handler = new FileHandler(src_path, dest_path, mode);
    if (!file_handler->is_opened()) return false;

    byte *cipher_key = new byte[key.length()], *_table = new byte[0x100];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];
    generate_cipher_bytes(cipher_key, key.length(), _table, mode);

    if (mode == XrcMode::DECRYPT) {
        std::string hash   = file_handler->read_hash();
        byte       *b_data = new byte[key.length()];
        for (size_t i = 0; i < key.length(); i++) b_data[i] = reinterpret_cast<const byte &>(key[i]);

        std::string gen_hash = HMAC_SHA256::toString(HMAC_SHA256::hmac(cipher_key, key.length(), b_data, key.length()));
        if (gen_hash != hash) {
            return false;
        }
    }

    byte64 file_length = std::filesystem::file_size(src_path);
    print_status("File size         = " + std::to_string(file_length / 1024ULL / 1024ULL) + " MB");
    file_handler->dispatch_writer_thread(mStatusListener);

    std::mutex              m;
    std::atomic<byte64>     thread_count = 0;
    std::condition_variable condition;

    byte64 chunk = 0, p_chunk = 0, read_time = 0, total_chunks = file_handler->get_buffer_mgr()->get_pool_size();
    catch_progress("Processing chunks", &p_chunk, total_chunks);

    auto begin = std::chrono::steady_clock::now();
    for (; chunk < total_chunks; chunk++) {
        auto read_beg = std::chrono::steady_clock::now();
        file_handler->read_file(chunk);
        read_time += std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_beg).count();

        thread_pool->queue(
                [&thread_count, &condition,
                 &mode, &_table, this](byte *_src, byte64 _s_len, const byte *_cipher, byte64 _c_len,
                                       byte64 chunk_idx, byte64 *p_chunk, FileHandler *fileManager, byte64 total_chunks) -> void {
                    if (mode == XrcMode::ENCRYPT) {
                        encrypt_bytes(_src, _s_len, _cipher, _c_len, _table);
                    } else {
                        decrypt_bytes(_src, _s_len, _cipher, _c_len, _table);
                    }
                    (*p_chunk)++;
                    catch_progress("Processing chunks", p_chunk, total_chunks);

                    if (fileManager != nullptr) {
                        fileManager->queue_chunk(chunk_idx);
                    } else {
                        print_status("File manager null #" + std::to_string(chunk_idx));
                    }

                    thread_count++;
                    condition.notify_all();
                },
                file_handler->get_buffer_mgr()->get_buffer(chunk),
                file_handler->get_buffer_mgr()->get_buffer_len(chunk),
                cipher_key, key.length(), chunk, &p_chunk, file_handler, total_chunks);
    }
    std::unique_lock<std::mutex> lock(m);
    condition.wait(lock, [&]() -> bool { return thread_count == total_chunks; });

    byte64 end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_status("Time taken        = " + std::to_string(end) + " ms");
    print_status(" `- Read time     = " + std::to_string(read_time) + " ms");
    end -= read_time;
    print_status(" `- Process time  = " + std::to_string(end) + " ms\n");
    print_speed(file_length, end);

    catch_progress("", nullptr, 0);
    auto _ret = file_handler->wrap_up(cipher_key, key);

    delete[] cipher_key;
    delete[] _table;
    delete file_handler;

    if (!preserve_src) {
        if (!std::filesystem::remove(src_path)) print_status("\n--- Could not delete source file ---\n");
    }
    return _ret;
}

void XorCryptor::print_speed(byte64 fileSize, byte64 time_end) {
    const byte64 KILO_BYTE = byte64(1024) * byte64(sizeof(unsigned char));
    const byte64 MEGA_BYTE = byte64(1024) * KILO_BYTE;

    std::string unit;
    if (fileSize >= MEGA_BYTE) {
        unit = " MB/s";
        fileSize /= MEGA_BYTE;
    } else {
        unit = " KB/s";
        fileSize /= KILO_BYTE;
    }
    long double speed = (long double) fileSize / (long double) time_end * 1000.0;

    std::stringstream str_speed;
    str_speed << std::fixed << std::setprecision(2) << speed;
    print_status("Processed bytes in " + std::to_string(time_end) + " [ms] - " + str_speed.str() + unit);
}

void XorCryptor::print_status(const std::string &status) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->print_status(status);
}

void XorCryptor::catch_progress(const std::string &status, XorCryptor::byte64 *progress_ptr, XorCryptor::byte64 total) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->catch_progress(status, progress_ptr, total);
}

bool XorCryptor::encrypt_file(bool preserve_src, ThreadPool *thread_pool,
                              const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, thread_pool, XrcMode::ENCRYPT, preserve_src);
}

bool XorCryptor::decrypt_file(bool preserve_src, ThreadPool *thread_pool,
                              const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, thread_pool, XrcMode::DECRYPT, preserve_src);
}

/// =================================================================================================
/// XorCryptor::FileHandler
/// =================================================================================================

void FileHandler::read_file(byte64 buff_idx) {
    std::lock_guard<std::mutex> lock_guard(_file_lock);
    _src_file.read((char *) buffer_manager->get_buffer(buff_idx), std::streamsize(buffer_manager->get_buffer_len(buff_idx)));
}

std::string FileHandler::read_hash() {
    _src_file.seekg(-64, std::ios::end);
    char *buff = new char[64];
    _src_file.read(buff, 64);
    _src_file.seekg(0, std::ios::beg);
    std::string hash(buff);
    return hash;
}

void FileHandler::queue_chunk(byte64 chunk_idx) {
    std::lock_guard<std::mutex> lock_guard(_file_lock);
    buff_queue[chunk_idx] = (int64_t) chunk_idx;
}

void FileHandler::dispatch_writer_thread(XorCryptor::StatusListener *instance) {
    if (file_writer_thread != nullptr) return;
    file_writer_thread = new std::thread(
            [this](XorCryptor::StatusListener *instance) -> void {
                byte64 curr_chunk_id = 0;
                while (curr_chunk_id < buffer_manager->get_pool_size()) {
                    while (buff_queue[curr_chunk_id] == -1) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                    if (instance != nullptr) instance->catch_progress("Writing chunk", &curr_chunk_id, buffer_manager->get_pool_size());
                    _out_file.write((char *) buffer_manager->get_buffer(curr_chunk_id), std::streamsize(buffer_manager->get_buffer_len(curr_chunk_id)));
                    buffer_manager->free_buffer(curr_chunk_id);
                    curr_chunk_id++;
                }

                if (instance != nullptr) instance->catch_progress("", nullptr, 0);
                thread_complete = true;
                condition.notify_one();
            },
            instance);
    file_writer_thread->detach();
}

void FileHandler::wait_writer_thread() {
    std::unique_lock<std::mutex> lock(thread_m);
    if (thread_complete) return;
    condition.wait(lock, [&]() -> bool { return thread_complete; });
}

bool FileHandler::wrap_up(const byte *key, const std::string &data) {
    wait_writer_thread();

    if (mode == XorCryptor::XrcMode::ENCRYPT) {
        byte *b_data = new byte[data.length()];
        for (size_t i = 0; i < data.length(); i++) b_data[i] = reinterpret_cast<const byte &>(data[i]);

        std::string hash = HMAC_SHA256::toString(HMAC_SHA256::hmac(key, data.length(), b_data, data.length()));
        _out_file.write(hash.c_str(), std::streamsize(hash.length()));
    }
    _src_file.close();
    _out_file.close();
    return !_src_file.is_open() && !_out_file.is_open();
}
