#include "cli.hpp"

int exec_cli_file(cli::CmdArgs *cmd_args, const std::string &progress, size_t idx, const std::string &key,
                  cli::ProgressIndicator *cli_pr, XorCryptor *xrc);

int process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, cli::CmdArgs *cmd_args,
                 cli::ProgressIndicator *cli_pr, XorCryptor *xrc);

// struct Status : XorCryptor::StatusListener {
//     ProgressIndicator *progressIndicator;
//     bool               verbose;
//
//     explicit Status(ProgressIndicator *indicator, bool verbose) : progressIndicator(indicator),
//                                                                   verbose(verbose) {}
//
//     void print_status(const std::string &status, bool imp) override {
//         if (imp) {
//             progressIndicator->print_status(status);
//             return;
//         }
//         if (verbose) progressIndicator->print_status(status);
//     }
//
//     void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) override {
//         if (verbose) {
//             progressIndicator->update_status(status);
//             progressIndicator->catch_progress(progress_ptr, total);
//         }
//     }
// };

int main(int argc, char *argv[]) {
    if (argc == 1) {
        cli::print_help();
        return 0;
    }

    std::vector<std::string> args(argc);
    for (int i = 1; i < argc; i++) {
        args[i - 1] = std::string(argv[i]);
        if (args[i - 1] == "-h" || args[i - 1] == "--help") {
            cli::print_help();
            return 0;
        }
    }

    auto *cmd_args = cli::CmdArgs::parse_args(args);
    if (cmd_args == nullptr) return 1;

    std::string key;
    std::cout << "\nEnter key: ";
    std::cin >> key;

    if (key.length() < 6) {
        std::cout << "Key cannot be less than 6 characters\n";
        return 1;
    }

    auto *cli = new cli::ProgressIndicator();
    auto *xrc = new XorCryptor(reinterpret_cast<const uint8_t *>(key.data()), key.length());
    cli->start_progress();

    auto *pool = new BS::thread_pool(std::thread::hardware_concurrency());
    int   res = 0, count = 0;
    for (size_t i = 0; i < cmd_args->get_files()->size(); i++) {
        count++;
        pool->push_task(
                [](int count, int *res, size_t idx, const std::string &key,
                   cli::CmdArgs *cmd_args, cli::ProgressIndicator *cli, XorCryptor *xrc) -> void {
                    if (exec_cli_file(cmd_args,
                                      "[" + std::to_string(count) + " / " + std::to_string(cmd_args->get_files()->size()) + "] ",
                                      idx, key, cli, xrc)) {
                        *res = 1;
                    }
                },
                count, &res, i, key, cmd_args, cli, xrc);
    }
    pool->wait_for_tasks();
    delete pool;

    cli->print_status("All jobs queued");
    cli->stop_progress();
    delete cli;
    delete xrc;

    std::cout << (cmd_args->get_mode() == XorCryptor::ENCRYPT ? "Encryption Completed\n" : "Decryption Completed\n");
    return res;
}

void safe_delete_arr(uint8_t *arr, size_t l_arr) {
    for (size_t i = 0; i < l_arr; i++) arr[i] = 0;
    delete[] arr;
}

int exec_cli_file(cli::CmdArgs *cmd_args, const std::string &progress, size_t idx, const std::string &key,
                  cli::ProgressIndicator *cli_pr, XorCryptor *xrc) {
    const std::filesystem::path file_path = (*cmd_args->get_files())[idx];
    std::string                 file_name = file_path.string();
    std::string                 dest_file_name(file_name);
    bool                        res;

    auto parent     = file_path.parent_path().parent_path().string();
    auto short_path = file_path.string().replace(0, parent.length(), "...");
    if (cmd_args->get_verbose()) {
        cli_pr->print_status("\nProcessing: " + short_path);
    } else {
        cli_pr->catch_progress(nullptr, 0);
        cli_pr->update_status(progress + " - " + short_path);
    }
    try {
        if (cmd_args->get_mode() == XorCryptor::Mode::ENCRYPT) {
            if (dest_file_name.find(cli::FileHandler::FILE_EXTENSION) != std::string::npos) {
                cli_pr->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(cli::FileHandler::FILE_EXTENSION);
            res = process_file(file_name, dest_file_name, key, cmd_args, cli_pr, xrc);
        } else {
            if (dest_file_name.find(cli::FileHandler::FILE_EXTENSION) == std::string::npos) {
                cli_pr->print_status("This file is not for decryption");
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res            = process_file(file_name, dest_file_name, key, cmd_args, cli_pr, xrc);
        }
    } catch (std::exception &e) {
        std::cout << file_name + " == Error: " + std::string(e.what()) + "\n";
        return 1;
    }
    if (res) {
        if (cmd_args->get_verbose()) {
            cli_pr->print_status(progress + (cmd_args->get_mode() == XorCryptor::Mode::ENCRYPT ? "Encrypted -> " + dest_file_name : "Decrypted -> " + dest_file_name));
        }
    }
    return !res;
}

int process_file(const std::string &src_path, const std::string &dest_path, const std::string &key, cli::CmdArgs *cmd_args,
                 cli::ProgressIndicator *cli_pr, XorCryptor *xrc) {
    auto  mode         = cmd_args->get_mode();
    auto *file_handler = new cli::FileHandler(src_path, dest_path, mode);
    if (!file_handler->is_opened()) return false;

    uint8_t *hash = HMAC_SHA256::hmac(xrc->get_cipher(), key.length(),
                                      reinterpret_cast<const uint8_t *>(key.data()), key.length());

    if (mode == XorCryptor::Mode::DECRYPT) {
        uint8_t *r_hash  = file_handler->read_hash();
        bool     match_f = [](const uint8_t *x, const uint8_t *y) -> bool {
            for (size_t i = 0; i < 32; i++) {
                if (x[i] != y[i]) return true;
            }
            return false;
        }(r_hash, hash);
        safe_delete_arr(r_hash, 32);

        if (match_f) {
            file_handler->wrap_up();
            std::filesystem::remove(dest_path);
            throw std::runtime_error("Wrong key");
        }
    } else {
        file_handler->write_hash(hash);
    }
    safe_delete_arr(hash, 32);

    uint64_t file_length = std::filesystem::file_size(src_path);
    if (cmd_args->get_verbose()) cli_pr->print_status("File size         = " + std::to_string(file_length / 1024ULL / 1024ULL) + " MB");
    file_handler->dispatch_writer_thread(cmd_args->get_verbose() ? cli_pr : nullptr);

    uint64_t chunk = 0, p_chunk = 0, read_time = 0, total_chunks = file_handler->get_buffer_mgr()->get_pool_size();
    if (cmd_args->get_verbose()) cli_pr->catch_progress("Processing chunks", &p_chunk, total_chunks);

    auto  begin = std::chrono::steady_clock::now();
    auto *pool  = new BS::thread_pool(std::thread::hardware_concurrency());
    for (; chunk < total_chunks; chunk++) {
        auto read_beg = std::chrono::steady_clock::now();
        file_handler->read_file(chunk);
        read_time += std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - read_beg).count();

        pool->push_task(
                [&mode, &file_handler, &cli_pr](uint8_t *src, uint64_t l_src, uint64_t chunk_idx, uint64_t *p_chunk,
                                                XorCryptor *xrc, uint64_t total_chunks, bool verbose) -> void {
                    if (mode == XorCryptor::Mode::ENCRYPT) {
                        xrc->encrypt_bytes(src, l_src);
                    } else {
                        xrc->decrypt_bytes(src, l_src);
                    }
                    (*p_chunk)++;
                    if (verbose) cli_pr->catch_progress("Processing chunks", p_chunk, total_chunks);
                    file_handler->queue_chunk(chunk_idx);
                },
                file_handler->get_buffer_mgr()->get_buffer(chunk),
                file_handler->get_buffer_mgr()->get_buffer_len(chunk),
                chunk, &p_chunk, xrc, total_chunks, cmd_args->get_verbose());
    }
    pool->wait_for_tasks();
    delete pool;

    if (cmd_args->get_verbose()) {
        uint64_t end = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - begin).count();
        cli_pr->print_status("Time taken        = " + std::to_string(end) + " ms");
        cli_pr->print_status(" `- Read time     = " + std::to_string(read_time) + " ms");
        end -= read_time;
        cli_pr->print_status(" `- Process time  = " + std::to_string(end) + " ms\n");
        cli::print_speed(cli_pr, file_length, end);
        cli_pr->catch_progress("", nullptr, 0);
    }
    auto _ret = file_handler->wrap_up();
    delete file_handler;

    if (!cmd_args->get_preserve_src()) {
        if (!std::filesystem::remove(src_path)) cli_pr->print_status("\n--- Could not delete source file ---\n");
    }
    return _ret;
}
