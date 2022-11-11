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

#include "hmac_sha256.h"

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
        virtual void print_status(const std::string &status, bool imp) = 0;

        /// @brief  Catches the progress of the current operation
        virtual void catch_progress(const std::string &status, byte64 *progress_ptr, byte64 total) = 0;

        virtual ~StatusListener() = 0;
    };

    enum XrcMode { ENCRYPT,
                   DECRYPT,
                   INVALID };

private:
    class BufferManager {
    private:
        /// @brief Size of the buffer chunk
        const byte64 CHUNK_SIZE = byte64(1024 * 1024 * 64);    // 64 MB

        byte  **buffer_pool = nullptr;
        byte64 *buffer_len  = nullptr;
        byte64  pool_size   = 0;

    public:
        explicit BufferManager(byte64 complete_length);

        [[nodiscard]] byte *get_buffer(byte64 index) const;

        [[nodiscard]] byte64 get_buffer_len(byte64 index) const { return buffer_len[index]; }

        [[nodiscard]] byte64 get_pool_size() const { return pool_size; }

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

    class FileHandler {
    private:
        std::mutex   _file_lock;
        std::fstream _src_file, _out_file;

        BufferManager      *buffer_manager;
        XorCryptor::XrcMode mode;
        int64_t            *buff_queue;
        bool                is_open = false;

        std::mutex              thread_m;
        std::condition_variable condition;
        std::atomic<bool>       thread_complete    = false;
        std::thread            *file_writer_thread = nullptr;

        /// @brief             Waits for the writer thread to complete
        void wait_writer_thread();

    public:
        FileHandler(const std::string &src_path, const std::string &dest_path, const XorCryptor::XrcMode &xrc_mode);

        BufferManager *get_buffer_mgr() const { return buffer_manager; }

        bool is_opened() const { return is_open; }

        std::string read_hash();
        void        write_hash(const std::string *hash);
        void        read_file(byte64 buff_idx);
        void        queue_chunk(byte64 chunk_id);
        void        dispatch_writer_thread(XorCryptor::StatusListener *instance);
        bool        wrap_up();

        ~FileHandler() {
            if (file_writer_thread->joinable()) file_writer_thread->join();
            delete file_writer_thread;
            delete buffer_manager;
            delete[] buff_queue;
        }
    };

    StatusListener *mStatusListener = nullptr;

    static byte         generate_mask(byte _v);
    static void         generate_cipher_bytes(byte *_cipher, byte64 _k_len, byte *_table, const XrcMode &xrc_mode);
    static void         encrypt_bytes(byte *_src, byte64 _len, const byte *_cipher, byte64 _k_len, const byte *_table);
    static void         decrypt_bytes(byte *_src, byte64 _src_len, const byte *_cipher, byte64 _k_len, const byte *_table);
    static std::string *generate_hash(const byte *cipher, const std::string &key);

    bool process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, const XrcMode &mode, bool preserve_src);
    void print_status(const std::string &status, bool imp = false) const;
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
    bool encrypt_file(bool preserve_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener);

    /// @brief              Decrypts the file
    /// @param preserve_src Src file shall be deleted when true
    /// @param src_path     The source file path
    /// @param dest_path    The destination file path
    /// @param key          The key to decrypt
    /// @param listener     The status listener
    /// @return             true if the file is decrypted successfully, else false
    bool decrypt_file(bool preserve_src, const std::string &src_path, const std::string &dest_path, const std::string &key, StatusListener *listener);

    ~XorCryptor() { mStatusListener = nullptr; }
};

#endif    // XOR_CRYPTOR_H
