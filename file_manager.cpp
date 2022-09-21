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

#include "file_manager.h"

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
    buffer_pool[chunk_id] = buff;
    buffer_length[chunk_id] = buff_len;
}

void FileManager::dispatch_writer_thread() {
    if (file_writer_thread != nullptr) return;
    file_writer_thread = new std::thread([this]() -> void {
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
            std::cout << "Writing #" << curr_chunk_id << "\n";
            _out_file.write((char *) buffer_pool[curr_chunk_id], std::streamsize(buffer_length[curr_chunk_id]));
            delete[] buffer_pool[curr_chunk_id];
            buffer_pool[curr_chunk_id] = nullptr;
            curr_chunk_id++;
        }

        thread_complete = true;
        condition.notify_all();
    });
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
