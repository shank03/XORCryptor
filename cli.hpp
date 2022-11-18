#ifndef CLI
#define CLI

#include "HMAC/hmac_sha256.h"
#include "XRC/xor_cryptor.h"
#include "all.h"

namespace cli {

    typedef unsigned char byte;
    typedef uint64_t      byte64;

    void print_help(bool error = false) {
        std::cout << "\n";
        if (!error) std::cout << "XOR Cryptor\n\n";
        std::cout << "Usage:\n - xor_cryptor [-p] [-r] [-v] -[e/d] -f [files...] [folders...]\n\n";
        std::cout << "Parameters:\n";
        std::cout << "    -p                    - Preserves the source file\n";
        std::cout << "    -r                    - Iterates recursively if any folder found in args\n";
        std::cout << "    -v                    - Verbose; Prints all the possible stats\n";
        std::cout << "    -e/d                  - encryption/decryption\n";
        std::cout << "    -f <files/folders>... - Encrypts/Decrypts the file(s) mentioned.\n";
    }

    void print_error(const std::string &error) {
        std::cout << "\nError: " << error << "\n";
        print_help(true);
    }

    void list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files, XorCryptor::Mode &mode) {
        std::queue<std::filesystem::path> queue;
        queue.push(root_path);
        while (!queue.empty()) {
            auto path = queue.front();
            queue.pop();

            try {
                for (const auto &entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_directory()) {
                        queue.push(entry);
                        continue;
                    }
                    if (entry.is_regular_file()) {
                        if (mode == XorCryptor::Mode::DECRYPT && entry.path().extension() == ".xrc") files->push_back(entry.path());
                        if (mode == XorCryptor::Mode::ENCRYPT && entry.path().extension() != ".xrc") files->push_back(entry.path());
                    }
                }
            } catch (std::exception &e) {
                std::cout << e.what() << "\n";
            }
        }
    }

    class CmdArgs {
    private:
        std::vector<std::filesystem::path> *files;

        bool             preserve_src;
        bool             verbose;
        XorCryptor::Mode mode;

        CmdArgs(std::vector<std::filesystem::path> *p_files,
                bool has_preserve_src, bool has_verbose,
                XorCryptor::Mode m) : files(p_files),
                                      preserve_src(has_preserve_src),
                                      verbose(has_verbose),
                                      mode(m) {
        }

    public:
        [[nodiscard]] std::vector<std::filesystem::path> *get_files() const { return files; }

        [[nodiscard]] bool get_preserve_src() const { return preserve_src; }

        [[nodiscard]] bool get_verbose() const { return verbose; }

        [[nodiscard]] XorCryptor::Mode get_mode() const { return mode; }

        static CmdArgs *parse_args(std::vector<std::string> &args) {
            auto *file_args = new std::vector<std::filesystem::path>(),
                 *files     = new std::vector<std::filesystem::path>();

            XorCryptor::Mode mode         = XorCryptor::Mode::INVALID;
            bool             preserve_src = false, recursive = false, verbose = false;
            for (size_t i = 0; i < args.size(); i++) {
                if (args[i] == "-p") preserve_src = true;
                if (args[i] == "-r") recursive = true;
                if (args[i] == "-v") verbose = true;
                if (args[i] == "-e") {
                    if (mode != XorCryptor::Mode::INVALID) {
                        print_error("Multiple modes found. Already defined: Decrypt");
                        return nullptr;
                    }
                    mode = XorCryptor::Mode::ENCRYPT;
                }
                if (args[i] == "-d") {
                    if (mode != XorCryptor::Mode::INVALID) {
                        print_error("Multiple modes found. Already defined: Encrypt");
                        return nullptr;
                    }
                    mode = XorCryptor::Mode::DECRYPT;
                }
                if (args[i] == "-f") {
                    if (i + 1 >= args.size()) {
                        print_error("No file(s)");
                        return nullptr;
                    }
                    i++;
                    while (i < args.size() && args[i][0] != '-') file_args->emplace_back(args[i++]);
                    i--;
                }
            }
            if (file_args->empty()) {
                print_error("No file(s)");
                return nullptr;
            }

            std::cout << "Retrieving files ...\n";
            for (auto &path : *file_args) {
                if (std::filesystem::is_regular_file(path)) {
                    if (mode == XorCryptor::Mode::DECRYPT && path.extension() == ".xrc") files->push_back(path);
                    if (mode == XorCryptor::Mode::ENCRYPT && path.extension() != ".xrc") files->push_back(path);
                }
                if (std::filesystem::is_directory(path)) {
                    if (recursive) {
                        list_all_files(path, files, mode);
                    } else {
                        for (const auto &entry : std::filesystem::directory_iterator(path)) {
                            if (entry.is_directory()) continue;
                            if (entry.is_regular_file()) {
                                if (mode == XorCryptor::Mode::DECRYPT && entry.path().extension() == ".xrc") files->push_back(entry.path());
                                if (mode == XorCryptor::Mode::ENCRYPT && entry.path().extension() != ".xrc") files->push_back(entry.path());
                            }
                        }
                    }
                }
            }
            if (files->empty()) {
                print_error("No " + std::string(mode == XorCryptor::Mode::DECRYPT ? ".xrc " : "") + "file(s) found");
                return nullptr;
            }
            std::cout << files->size() << (mode == XorCryptor::Mode::DECRYPT ? " .xrc" : "") << " file(s) found\n";
            return new CmdArgs(files, preserve_src, verbose, mode);
        }
    };

    class ProgressIndicator {
        std::string       s_pre_indicator_text;
        std::atomic<bool> run_indicator = false;

        uint64_t        *p_progress = nullptr;
        long double      _total     = 0;
        std::atomic<int> last_len   = 0;

        std::mutex              m_thread;
        std::condition_variable condition_v;
        std::atomic<bool>       thread_completed  = false;
        std::thread            *p_progress_thread = nullptr;

    public:
        void start_progress() {
            if (p_progress_thread != nullptr) return;
            run_indicator = true;

            p_progress_thread = new std::thread([this]() -> void {
                std::vector<std::string> progress_indicator { "-", "\\", "|", "/" };
                int                      idx = 0;
                last_len                     = (int) s_pre_indicator_text.length();
                while (run_indicator) {
                    if (idx == (int) progress_indicator.size()) idx = 0;

                    std::cout << "\r" << std::string(last_len, ' ') << "\r";
                    std::cout.flush();
                    std::cout << s_pre_indicator_text << " " << progress_indicator[idx++];

                    int len = (int) s_pre_indicator_text.length() + 3;
                    if (p_progress != nullptr && _total != 0) {
                        auto        upper      = std::min((long double) *p_progress, _total);
                        long double percentage = (upper * 100.0) / _total;

                        std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
                        len += 20;
                    }
                    last_len = len;

                    std::cout.flush();
                    std::cout << "\r";
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
                std::cout << "\r" << std::string(last_len, ' ') << "\r";
                std::cout.flush();
                std::cout << s_pre_indicator_text << "\n";

                thread_completed = true;
                condition_v.notify_one();
            });
        }

        void stop_progress() {
            if (p_progress_thread == nullptr) return;

            std::unique_lock<std::mutex> lock(m_thread);
            run_indicator = false;
            p_progress    = nullptr;
            p_progress_thread->join();
            condition_v.wait(lock, [this]() -> bool { return thread_completed; });
            p_progress_thread = nullptr;
        }

        void print_status(const std::string &status) {
            _total = 0;
            std::cout << "\r" << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << status << "\n";
        }

        void update_status(const std::string &stat) { s_pre_indicator_text = stat; }

        void catch_progress(uint64_t *progress, uint64_t total) {
            p_progress = progress;
            _total     = (long double) total;
        }

        void catch_progress(const std::string &stat, uint64_t *progress, uint64_t total) {
            update_status(stat);
            catch_progress(progress, total);
        }
    };

    class BufferManager {
    private:
        /// @brief Size of the buffer chunk
        const byte64 CHUNK_SIZE = byte64(1024 * 1024 * 64);    // 64 MB

        byte  **buffer_pool = nullptr;
        byte64 *buffer_len  = nullptr;
        byte64  pool_size   = 0;

    public:
        explicit BufferManager(byte64 complete_length) {
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

        [[nodiscard]] byte *get_buffer(byte64 index) const {
            if (buffer_pool[index] == nullptr) buffer_pool[index] = new byte[buffer_len[index]];
            return buffer_pool[index];
        }

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
        std::mutex   m_file_lock;
        std::fstream f_src_file, f_out_file;

        BufferManager   *buffer_manager;
        XorCryptor::Mode mode;
        int64_t         *buff_queue;
        bool             is_open = false;

        std::mutex              m_thread;
        std::condition_variable condition_v;
        std::atomic<bool>       thread_completed     = false;
        std::thread            *p_file_writer_thread = nullptr;

        /// @brief             Waits for the writer thread to complete
        void wait_writer_thread() {
            std::unique_lock<std::mutex> lock(m_thread);
            if (p_file_writer_thread == nullptr) return;
            condition_v.wait(lock, [&]() -> bool { return thread_completed; });
        }

    public:
        inline static const std::string FILE_EXTENSION = ".xrc";

        FileHandler(const std::string &src_path, const std::string &dest_path, const XorCryptor::Mode &xrc_mode) {
            if (std::filesystem::is_directory(src_path)) {
                is_open = false;
                return;
            }
            f_src_file.open(src_path, std::ios::in | std::ios::binary);
            if (!f_src_file.is_open() || !f_src_file) {
                is_open = false;
                return;
            }
            f_out_file.open(dest_path, std::ios::out | std::ios::binary);
            if (!f_out_file.is_open() || !f_out_file) {
                is_open = false;
                return;
            }
            mode               = xrc_mode;
            byte64 file_length = std::filesystem::file_size(src_path);
            if (mode == XorCryptor::Mode::DECRYPT) file_length -= 32ULL;

            buffer_manager = new BufferManager(file_length);
            buff_queue     = new int64_t[buffer_manager->get_pool_size()];
            is_open        = f_src_file.is_open() && f_out_file.is_open();
            std::fill(buff_queue, buff_queue + buffer_manager->get_pool_size(), -1);
        }

        BufferManager *get_buffer_mgr() const { return buffer_manager; }

        bool is_opened() const { return is_open; }

        byte *read_hash() {
            byte *buff = new byte[32];
            f_src_file.read((char *) buff, 32);
            return buff;
        }

        void write_hash(const byte *hash) { f_out_file.write((char *) hash, 32); }

        void read_file(byte64 buff_idx) {
            std::lock_guard<std::mutex> lock_guard(m_file_lock);
            if (!f_src_file.read((char *) buffer_manager->get_buffer(buff_idx), std::streamsize(buffer_manager->get_buffer_len(buff_idx)))) {
                throw std::runtime_error("Unable to read file");
            }
        }

        void queue_chunk(byte64 buff_idx) {
            std::lock_guard<std::mutex> lock_guard(m_file_lock);
            buff_queue[buff_idx] = (int64_t) buff_idx + 1;
        }

        void dispatch_writer_thread(ProgressIndicator *instance) {
            if (p_file_writer_thread != nullptr) return;
            p_file_writer_thread = new std::thread(
                    [this](ProgressIndicator *instance) -> void {
                        byte64 curr_chunk_id = 0;
                        while (curr_chunk_id < buffer_manager->get_pool_size()) {
                            while (buff_queue[curr_chunk_id] == -1) {
                                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                            }
                            if (instance != nullptr) instance->catch_progress("Writing chunk", &curr_chunk_id, buffer_manager->get_pool_size());
                            f_out_file.write((char *) buffer_manager->get_buffer(curr_chunk_id), std::streamsize(buffer_manager->get_buffer_len(curr_chunk_id)));
                            buffer_manager->free_buffer(curr_chunk_id);
                            curr_chunk_id++;
                        }

                        if (instance != nullptr) instance->catch_progress("", nullptr, 0);
                        thread_completed = true;
                        condition_v.notify_one();
                    },
                    instance);
            p_file_writer_thread->detach();
        }

        bool wrap_up() {
            wait_writer_thread();
            f_src_file.close();
            f_out_file.close();
            return !f_src_file.is_open() && !f_out_file.is_open();
        }

        ~FileHandler() {
            if (p_file_writer_thread->joinable()) p_file_writer_thread->join();
            delete p_file_writer_thread;
            delete buffer_manager;
            delete[] buff_queue;
        }
    };

    void print_speed(ProgressIndicator *cli_pr, byte64 fileSize, byte64 time_end) {
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
        cli_pr->print_status("Processed bytes in " + std::to_string(time_end) + " [ms] - " + str_speed.str() + unit);
    }
}    // namespace cli

#endif    // CLI
