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

#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <atomic>
#include <condition_variable>
#include <fstream>
#include <mutex>
#include <thread>

class FileManager {
    typedef unsigned char byte;
    typedef uint64_t      byte64;

private:
    std::mutex   _file_lock;
    std::fstream _src_file, _out_file;

    byte  **buffer_pool   = nullptr;
    byte64 *buffer_length = nullptr;
    byte64  _num_chunks   = 0;
    bool    is_open       = false;

    std::mutex              thread_m;
    std::condition_variable condition;
    std::atomic<bool>       thread_complete    = false;
    std::thread            *file_writer_thread = nullptr;

public:
    FileManager(const std::string &src_path, const std::string &dest_path) {
        _src_file.open(src_path, std::ios::in | std::ios::binary);
        _out_file.open(dest_path, std::ios::out | std::ios::binary);
        is_open = _src_file.is_open() && _out_file.is_open();
    }

    bool is_opened() const { return is_open; }

    void read_file(byte *buff, byte64 buff_len);

    void init_write_chunks(byte64 chunks);

    void write_chunk(byte *buff, byte64 buff_len, byte64 chunk_id);

    void dispatch_writer_thread();

    void wait_writer_thread();

    bool close_file();

    ~FileManager() {
        if (file_writer_thread->joinable()) file_writer_thread->join();
        delete file_writer_thread;
        delete[] buffer_pool;
        delete[] buffer_length;
    }
};

#endif    // FILE_MANAGER_H
