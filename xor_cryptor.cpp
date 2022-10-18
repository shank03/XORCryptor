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

void XorCryptor::generate_cipher_bytes(byte *_cipher, byte64 _k_len, bool to_encrypt) const {
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
        mask                          = (mask << 4) | mode;
        _table[to_encrypt ? i : mask] = to_encrypt ? mask : i;
        mask = mode = 0;
    }
}

void XorCryptor::encrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len) const {
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

void XorCryptor::decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len) const {
    byte64 i, k = 0;
    byte64 odd = _src_len & 1;
    byte   mask, mode;
    for (i = 0; i < _src_len; i++) {
        mask = byte(_src[i] ^ _cipher[i % _k_len]);
        if (i == (_src_len - 1ULL) && odd) {
            mode = mask & 0xF;
            mask >>= 4;
            mode ^= mask;

            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
        } else {
            i++;
            mode = byte(_src[i] ^ _cipher[i % _k_len]);
            mode ^= mask;

            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
            mask >>= 4, mode >>= 4;
            _src[k++] = _table[((mask & 0xF) << 4) | (mode & 0xF)];
        }
    }
}

bool XorCryptor::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt) {
    FileManager *fileManager = new FileManager(src_path, dest_path);
    if (!fileManager->is_opened()) return false;

    byte *cipher_key = new byte[key.length()];
    for (byte64 i = 0; i < key.length(); i++) cipher_key[i] = key[i];

    _table = new byte[0x100];
    generate_cipher_bytes(cipher_key, key.length(), to_encrypt);

    byte64 file_length  = std::filesystem::file_size(src_path);
    byte64 total_chunks = file_length / CHUNK_SIZE;
    byte64 last_chunk   = file_length % CHUNK_SIZE;
    if (last_chunk != 0) {
        total_chunks++;
    } else {
        last_chunk = CHUNK_SIZE;
    }
    fileManager->init_write_chunks(total_chunks);

    std::mutex              m;
    std::atomic<byte64>     thread_count = 0;
    std::atomic<byte64>     duration     = 0;
    std::condition_variable condition;

    fileManager->dispatch_writer_thread(mStatusListener);

    byte64 chunk = 0, p_chunk = 0, read_time = 0;
    auto   begin = std::chrono::steady_clock::now();
    catch_progress("Processing chunks", &p_chunk, total_chunks);
    for (; chunk < total_chunks; chunk++) {
        byte64 chunk_length = chunk == total_chunks - 1 ? last_chunk : CHUNK_SIZE;
        byte  *buffer       = new byte[chunk_length];

        auto read_beg = std::chrono::steady_clock::now();
        fileManager->read_file(buffer, chunk_length);
        read_time += std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_beg).count();

        std::thread(
                [&thread_count, &condition, &duration, &begin,
                 &to_encrypt, &total_chunks, this](byte *_src, byte64 _s_len, const byte *_cipher, byte64 _c_len,
                                                   byte64 chunk_idx, byte64 *p_chunk, FileManager *fileManager) -> void {
                    if (to_encrypt) {
                        encrypt_bytes(_src, _s_len, _cipher, _c_len);
                    } else {
                        decrypt_bytes(_src, _s_len, _cipher, _c_len);
                    }
                    (*p_chunk)++;
                    catch_progress("Processing chunks", p_chunk, total_chunks);

                    if (fileManager != nullptr) {
                        fileManager->write_chunk(_src, _s_len, chunk_idx);
                    } else {
                        print_status("File manager null #" + std::to_string(chunk_idx));
                    }

                    thread_count++;
                    condition.notify_all();
                },
                buffer, chunk_length, cipher_key, key.length(), chunk, &p_chunk, fileManager)
                .detach();
    }
    std::unique_lock<std::mutex> lock(m);
    condition.wait(lock, [&]() -> bool { return thread_count == total_chunks; });

    byte64 end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_status("\nFile size         = " + std::to_string(file_length / 1024ULL / 1024ULL) + " MB");
    print_status("Time taken        = " + std::to_string(end) + " ms");
    print_status(" `- Read time     = " + std::to_string(read_time) + " ms");
    end -= read_time;
    print_status(" `- Process time  = " + std::to_string(end) + " ms\n");
    print_speed(file_length, end);

    delete[] cipher_key;
    delete[] _table;
    _table = nullptr;

    catch_progress("Writing file", nullptr, 0);
    fileManager->wait_writer_thread();
    auto _ret = fileManager->close_file();
    delete fileManager;
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

bool XorCryptor::encrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, true);
}

bool XorCryptor::decrypt_file(const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, false);
}

/// =================================================================================================
/// XorCryptor::FileManager
/// =================================================================================================

void FileManager::read_file(FileManager::byte *buff, FileManager::byte64 buff_len) {
    std::lock_guard<std::mutex> lock_guard(_file_lock);
    _src_file.read((char *) buff, std::streamsize(buff_len));
}

void FileManager::init_write_chunks(FileManager::byte64 chunks) {
    _num_chunks = chunks;
    buffer_pool = new byte *[_num_chunks];
    std::fill(buffer_pool, buffer_pool + _num_chunks, nullptr);

    buffer_length = new byte64[_num_chunks];
    std::fill(buffer_length, buffer_length + _num_chunks, 0);
}

void FileManager::write_chunk(FileManager::byte *buff, FileManager::byte64 buff_len, FileManager::byte64 chunk_id) {
    if (buffer_pool == nullptr || buffer_length == nullptr) return;
    std::lock_guard<std::mutex> lock_guard(_file_lock);

    if (buffer_pool[chunk_id] != nullptr) return;
    buffer_pool[chunk_id]   = buff;
    buffer_length[chunk_id] = buff_len;
}

void FileManager::dispatch_writer_thread(XorCryptor::StatusListener *instance) {
    if (file_writer_thread != nullptr) return;
    file_writer_thread = new std::thread(
            [this](XorCryptor::StatusListener *instance) -> void {
                if (buffer_pool == nullptr || buffer_length == nullptr) {
                    thread_complete = true;
                    condition.notify_all();
                    return;
                }

                byte64 curr_chunk_id = 0;
                while (curr_chunk_id < _num_chunks) {
                    while (buffer_pool[curr_chunk_id] == nullptr) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    }
                    if (instance != nullptr) instance->catch_progress("Writing chunk", &curr_chunk_id, _num_chunks);
                    _out_file.write((char *) buffer_pool[curr_chunk_id], std::streamsize(buffer_length[curr_chunk_id]));
                    delete[] buffer_pool[curr_chunk_id];
                    buffer_pool[curr_chunk_id] = nullptr;
                    curr_chunk_id++;
                }

                thread_complete = true;
                condition.notify_all();
            },
            instance);
    file_writer_thread->detach();
}

void FileManager::wait_writer_thread() {
    std::unique_lock<std::mutex> lock(thread_m);
    condition.wait(lock, [&]() -> bool { return thread_complete; });
}

bool FileManager::close_file() {
    _src_file.close();
    _out_file.close();
    return !_src_file.is_open() && !_out_file.is_open();
}
