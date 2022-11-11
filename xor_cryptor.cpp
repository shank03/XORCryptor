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

std::string *XorCryptor::generate_hash(const byte *cipher, const std::string &key) {
    return new std::string(HMAC_SHA256::toString(
            HMAC_SHA256::hmac(cipher, key.length(), reinterpret_cast<const byte *>(key.data()), key.length())));
}

bool XorCryptor::process_file(const std::string &src_path, const std::string &dest_path, const std::string &key,
                              const XrcMode &mode, bool preserve_src) {
    auto *file_handler = new FileHandler(src_path, dest_path, mode);
    if (!file_handler->is_opened()) return false;

    byte *cipher = new byte[key.length()], *table = new byte[0x100];
    for (size_t i = 0; i < key.length(); i++) cipher[i] = key[i];
    generate_cipher_bytes(cipher, key.length(), table, mode);
    auto *hash = generate_hash(cipher, key);

    if (mode == XrcMode::DECRYPT) {
        std::string rh = file_handler->read_hash();
        if (rh != *hash) {
            file_handler->wrap_up();
            std::filesystem::remove(dest_path);
            throw std::runtime_error("Wrong key");
        }
    } else {
        file_handler->write_hash(hash);
    }

    byte64 file_length = std::filesystem::file_size(src_path);
    print_status("File size         = " + std::to_string(file_length / 1024ULL / 1024ULL) + " MB");
    file_handler->dispatch_writer_thread(mStatusListener);

    byte64 chunk = 0, p_chunk = 0, read_time = 0, total_chunks = file_handler->get_buffer_mgr()->get_pool_size();
    catch_progress("Processing chunks", &p_chunk, total_chunks);

    size_t                  max_jobs = std::thread::hardware_concurrency(), total_jobs = total_chunks;
    std::atomic<size_t>     queued_jobs = 0, completed_jobs = 0;
    std::mutex              hold_mutex, term_mutex;
    std::condition_variable hold_cv, term_cv;

    auto  begin   = std::chrono::steady_clock::now();
    auto *workers = new std::vector<std::thread *>(total_chunks, nullptr);
    for (; chunk < total_chunks; chunk++) {
        auto read_beg = std::chrono::steady_clock::now();
        file_handler->read_file(chunk);
        read_time += std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_beg).count();

        if (queued_jobs == max_jobs) {
            std::unique_lock<std::mutex> hold_lock(hold_mutex);
            hold_cv.wait(hold_lock, [&]() -> bool { return queued_jobs != max_jobs; });
        }
        queued_jobs++;
        (*workers)[chunk] = new std::thread(
                [&queued_jobs, &hold_cv, &completed_jobs, &term_cv,
                 &mode, &table, this](byte *_src, byte64 _s_len, const byte *_cipher, byte64 _c_len,
                                      byte64 chunk_idx, byte64 *p_chunk, FileHandler *fileManager, byte64 total_chunks) -> void {
                    if (mode == XrcMode::ENCRYPT) {
                        encrypt_bytes(_src, _s_len, _cipher, _c_len, table);
                    } else {
                        decrypt_bytes(_src, _s_len, _cipher, _c_len, table);
                    }
                    (*p_chunk)++;
                    catch_progress("Processing chunks", p_chunk, total_chunks);

                    if (fileManager != nullptr) {
                        fileManager->queue_chunk(chunk_idx);
                    } else {
                        print_status("File manager null #" + std::to_string(chunk_idx));
                    }

                    queued_jobs--;
                    hold_cv.notify_one();
                    completed_jobs++;
                    term_cv.notify_one();
                },
                file_handler->get_buffer_mgr()->get_buffer(chunk),
                file_handler->get_buffer_mgr()->get_buffer_len(chunk),
                cipher, key.length(), chunk, &p_chunk, file_handler, total_chunks);
    }
    for (auto &it : *workers) it->join();

    std::unique_lock<std::mutex> term_lock(term_mutex);
    term_cv.wait(term_lock, [&]() -> bool { return completed_jobs == total_jobs; });
    delete workers;

    byte64 end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
    print_status("Time taken        = " + std::to_string(end) + " ms");
    print_status(" `- Read time     = " + std::to_string(read_time) + " ms");
    end -= read_time;
    print_status(" `- Process time  = " + std::to_string(end) + " ms\n");
    print_speed(file_length, end);

    catch_progress("", nullptr, 0);
    auto _ret = file_handler->wrap_up();

    delete[] cipher;
    delete[] table;
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

void XorCryptor::print_status(const std::string &status, bool imp) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->print_status(status, imp);
}

void XorCryptor::catch_progress(const std::string &status, XorCryptor::byte64 *progress_ptr, XorCryptor::byte64 total) const {
    if (mStatusListener == nullptr) return;
    mStatusListener->catch_progress(status, progress_ptr, total);
}

bool XorCryptor::encrypt_file(bool preserve_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, XrcMode::ENCRYPT, preserve_src);
}

bool XorCryptor::decrypt_file(bool preserve_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener) {
    mStatusListener = listener;
    return process_file(src_path, dest_path, key, XrcMode::DECRYPT, preserve_src);
}

XorCryptor::FileHandler::FileHandler(const std::string &src_path, const std::string &dest_path, const XorCryptor::XrcMode &xrc_mode) {
    if (std::filesystem::is_directory(src_path)) {
        is_open = false;
        return;
    }
    _src_file.open(src_path, std::ios::in | std::ios::binary);
    if (!_src_file.is_open() || !_src_file) {
        is_open = false;
        return;
    }
    _out_file.open(dest_path, std::ios::out | std::ios::binary);
    if (!_out_file.is_open() || !_out_file) {
        is_open = false;
        return;
    }
    mode = xrc_mode;

    byte64 file_length = std::filesystem::file_size(src_path);
    if (mode == XorCryptor::XrcMode::DECRYPT) file_length -= 64ULL;
    buffer_manager = new BufferManager(file_length);
    buff_queue     = new int64_t[buffer_manager->get_pool_size()];
    is_open        = _src_file.is_open() && _out_file.is_open();
    std::fill(buff_queue, buff_queue + buffer_manager->get_pool_size(), -1);
}

void XorCryptor::FileHandler::read_file(byte64 buff_idx) {
    std::lock_guard<std::mutex> lock_guard(_file_lock);
    if (!_src_file.read((char *) buffer_manager->get_buffer(buff_idx), std::streamsize(buffer_manager->get_buffer_len(buff_idx)))) {
        throw std::exception();
    }
}

std::string XorCryptor::FileHandler::read_hash() {
    char *buff = new char[65];
    _src_file.read(buff, 64);
    buff[64] = '\0';
    std::string hash(buff);
    return hash;
}

void XorCryptor::FileHandler::write_hash(const std::string *hash) {
    _out_file.write(hash->data(), std::streamsize(hash->length()));
}

void XorCryptor::FileHandler::queue_chunk(byte64 chunk_idx) {
    std::lock_guard<std::mutex> lock_guard(_file_lock);
    buff_queue[chunk_idx] = (int64_t) chunk_idx + 1;
}

void XorCryptor::FileHandler::dispatch_writer_thread(XorCryptor::StatusListener *instance) {
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

void XorCryptor::FileHandler::wait_writer_thread() {
    std::unique_lock<std::mutex> lock(thread_m);
    if (file_writer_thread == nullptr) return;
    condition.wait(lock, [&]() -> bool { return thread_complete; });
}

bool XorCryptor::FileHandler::wrap_up() {
    wait_writer_thread();
    _src_file.close();
    _out_file.close();
    return !_src_file.is_open() && !_out_file.is_open();
}

XorCryptor::BufferManager::BufferManager(XorCryptor::byte64 complete_length) {
    byte64 total_chunks = complete_length / CHUNK_SIZE;
    byte64 last_chunk   = complete_length % CHUNK_SIZE;
    if (last_chunk != 0) {
        total_chunks++;
    } else {
        last_chunk = CHUNK_SIZE;
    }

    pool_size   = total_chunks;
    buffer_pool = new byte *[pool_size];
    buffer_len  = new byte64[pool_size];

    std::fill(buffer_pool, buffer_pool + pool_size, nullptr);
    for (byte64 i = 0; i < pool_size; i++) {
        buffer_len[i] = i == pool_size - 1 ? last_chunk : CHUNK_SIZE;
    }
}

XorCryptor::byte *XorCryptor::BufferManager::get_buffer(XorCryptor::byte64 index) const {
    if (buffer_pool[index] == nullptr) buffer_pool[index] = new byte[buffer_len[index]];
    return buffer_pool[index];
}
