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

#ifndef XOR_CRYPTOR_H
#define XOR_CRYPTOR_H

#include <atomic>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <mutex>
#include <queue>
#include <sstream>
#include <thread>
#include <vector>

/// @brief A class to encrypt/decrypt files using XOR encryption
class XorCryptor {
    typedef unsigned char byte;
    typedef uint64_t      byte64;

public:
    inline static const std::string FILE_EXTENSION = ".xrc";

    /// @brief Listener for progress
    struct StatusListener {
        /// @brief  Prints the status of the current operation
        /// @param status
        virtual void print_status(const std::string &status) = 0;

        /// @brief  Catches the progress of the current operation
        virtual void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) = 0;

        virtual ~StatusListener() = 0;
    };

private:
    StatusListener *mStatusListener = nullptr;
    byte           *_table          = nullptr;

    /// @brief      Generates mask for the given byte
    /// @param _v   Byte to generate mask for
    /// @return     Mask for the given byte
    static byte generate_mask(byte _v);

    /// @brief              Generates table for the given key
    /// @param _cipher      Key to generate table for
    /// @param _k_len       Length of the key
    /// @param to_encrypt   Whether to encrypt or decrypt
    void generate_cipher_bytes(byte *_cipher, byte64 _k_len, bool to_encrypt) const;

    /// @brief          Encrypts the buffer using the given key
    /// @param _src     Buffer to encrypt
    /// @param _len     Length of the buffer
    /// @param _cipher  Key to encrypt with
    /// @param _k_len   Length of the key
    void encrypt_bytes(byte *_src, byte64 _len, const byte *_cipher, byte64 _k_len) const;

    /// @brief              Decrypts the buffer using the given key
    /// @param _src         Buffer to decrypt
    /// @param _src_len     Length of the buffer
    /// @param _cipher      Key to decrypt with
    /// @param _k_len       Length of the key
    void decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len) const;

    /// @brief              Process the file
    /// @param src_path     Path of the file to be processed
    /// @param dest_path    Path of the processed file
    /// @param key          Key to process the file
    /// @param to_encrypt   If true, encrypts the file, else decrypts the file
    /// @param preserve_src If true, src file is deleted
    /// @return             Returns true if the file is processed successfully, else false
    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, bool to_encrypt, bool preverse_src);

    void print_status(const std::string &status) const;

    void print_speed(byte64 fileSize, byte64 time_end);

    void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) const;

public:
    XorCryptor() { mStatusListener = nullptr; }

    /// @brief              Encrypts the file
    /// @param preserve_src Src file shall be deleted when true
    /// @param src_path     The source file path
    /// @param dest_path    The destination file path
    /// @param key          The key to encrypt
    /// @param listener     The status listener
    /// @return             true if the file is encrypted/decrypted successfully, else false
    bool encrypt_file(bool preverse_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener);

    /// @brief              Decrypts the file
    /// @param preserve_src Src file shall be deleted when true
    /// @param src_path     The source file path
    /// @param dest_path    The destination file path
    /// @param key          The key to decrypt
    /// @param listener     The status listener
    /// @return             true if the file is decrypted successfully, else false
    bool decrypt_file(bool preverse_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener);

    ~XorCryptor() {
        delete mStatusListener;
        delete[] _table;
    }
};

class ThreadPool {
private:
    std::mutex              queue_mutex;
    std::condition_variable condition;
    std::atomic<bool>       stop = false;

    std::vector<std::thread>          worker_threads;
    std::queue<std::function<void()>> jobs;

public:
    ThreadPool(size_t threads = std::thread::hardware_concurrency()) {
        stop = false;
        for (size_t i = 0; i < threads; i++) {
            worker_threads.emplace_back([this] {
                for (;;) {
                    std::function<void()> job;
                    {
                        std::unique_lock<std::mutex> lock(queue_mutex);
                        condition.wait(lock, [&] { return stop || !jobs.empty(); });
                        if (stop && jobs.empty()) return;
                        job = std::move(jobs.front());
                        jobs.pop();
                    }
                    job();
                }
            });
        }
    }

    template <typename F, typename... A>
    auto queue(F &&f, A &&...args) {
        std::function<void()> task = std::bind(std::forward<F>(f), std::forward<A>(args)...);
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if (stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");
            jobs.emplace([task] { task(); });
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (auto &worker : worker_threads) worker.join();
    }
};

class BufferManager {
    typedef unsigned char byte;
    typedef uint64_t      byte64;

private:
    /// @brief Size of the buffer chunk
    const byte64 CHUNK_SIZE = byte64(1024 * 1024 * 64);    // 64 MB

    byte  **buffer_pool = nullptr;
    byte64 *buffer_len  = nullptr;
    byte64  pool_size   = 0;

public:
    BufferManager(byte64 complete_length) {
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

    byte *get_buffer(byte64 index) const {
        if (buffer_pool[index] == nullptr) {
            buffer_pool[index] = new byte[buffer_len[index]];
        }
        return buffer_pool[index];
    }

    byte64 get_buffer_len(byte64 index) const { return buffer_len[index]; }

    byte64 get_pool_size() const { return pool_size; }

    void free_buffer(byte64 index) {
        delete[] buffer_pool[index];
        buffer_pool[index] = nullptr;
        buffer_len[index]  = 0;
    }

    ~BufferManager() {
        for (byte64 i = 0; i < pool_size; i++) delete[] buffer_pool[i];
        delete[] buffer_pool;
        delete[] buffer_len;
    }
};

/// @brief File manager for the XorCryptor
class FileManager {
    typedef unsigned char byte;
    typedef uint64_t      byte64;

private:
    std::mutex   _file_lock;
    std::fstream _src_file, _out_file;

    BufferManager *buffer_manager = nullptr;
    int64_t       *buff_queue     = nullptr;
    bool           is_open        = false;

    std::mutex              thread_m;
    std::condition_variable condition;
    std::atomic<bool>       thread_complete    = false;
    std::thread            *file_writer_thread = nullptr;

    /// @brief             Waits for the writer thread to complete
    void wait_writer_thread();

public:
    FileManager(const std::string &src_path, const std::string &dest_path) {
        if (std::filesystem::is_directory(src_path)) {
            is_open = false;
            return;
        }
        _src_file.open(src_path, std::ios::in | std::ios::binary);
        if (!_src_file.is_open()) {
            is_open = false;
            return;
        }
        _out_file.open(dest_path, std::ios::out | std::ios::binary);
        is_open = _src_file.is_open() && _out_file.is_open();
    }

    /// @brief      Status of opened the files
    /// @return     true if the file is opened successfully, else false
    bool is_opened() const { return is_open; }

    /// @brief              Reads the buffer from @c _src_file into @param buff
    /// @param buff         Buffer size
    /// @param buff_len     Buffer length
    void read_file(byte *buff, byte64 buff_len);

    /// @brief            Initializes the buffer pool
    void init_buffer_queue(BufferManager *buff_mgr);

    /// @brief              Queue the buffer to write
    /// @param chunk_id     Chunk id
    void queue_chunk(byte64 chunk_id);

    /// @brief              Writes the buffer to the file in the
    ///                     order of the chunk id
    /// @param instance     Instance of the FileManager
    void dispatch_writer_thread(XorCryptor::StatusListener *instance);

    /// @brief      Closes the files and waits for writer thread to complete
    /// @return     true if the files are closed successfully, else false
    bool wrap_up();

    /// @brief      Destructor
    ~FileManager() {
        if (file_writer_thread->joinable()) file_writer_thread->join();
        delete file_writer_thread;
        delete buffer_manager;
        delete[] buff_queue;
    }
};

#endif    // XOR_CRYPTOR_H
