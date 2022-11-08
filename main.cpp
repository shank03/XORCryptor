#include <iostream>

#include "cli.h"
#include "xor_cryptor.h"

struct CmdArgs {
    std::vector<std::filesystem::path> *files;

    bool                preserve_src;
    bool                verbose;
    XorCryptor::XrcMode mode;

    CmdArgs(std::vector<std::filesystem::path> *p_files,
            bool has_preserve_src, bool has_verbose,
            XorCryptor::XrcMode m) : files(p_files),
                                     preserve_src(has_preserve_src),
                                     verbose(has_verbose),
                                     mode(m) {}
};

int      exec_cli_file(CmdArgs *cmd_args, const std::string &progress, const std::string &file_name, const std::string &key,
                       CLIProgressIndicator *cli, XorCryptor::StatusListener *status, XorCryptor *xrc, ThreadPool *thread_pool);
void     list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files);
CmdArgs *parse_args(std::vector<std::string> &args);
void     print_help(bool error = false);
void     print_error(const std::string &error);

struct Status : XorCryptor::StatusListener {
    CLIProgressIndicator *progressIndicator;
    bool                  verbose;

    explicit Status(CLIProgressIndicator *indicator, bool verbose) : progressIndicator(indicator),
                                                                     verbose(verbose) {}

    void print_status(const std::string &status, bool imp) override {
        if (imp) {
            progressIndicator->print_status(status);
            return;
        }
        if (verbose) progressIndicator->print_status(status);
    }

    void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) override {
        if (verbose) {
            progressIndicator->update_status(status);
            progressIndicator->catch_progress(progress_ptr, total);
        }
    }
};

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help();
        return 0;
    }

    std::vector<std::string> args(argc);
    for (int i = 0; i < argc; i++) {
        args[i] = std::string(argv[i]);
        if (args[i] == "-h" || args[i] == "--help") {
            print_help();
            return 0;
        }
    }

    auto *cmd_args = parse_args(args);
    if (cmd_args == nullptr) return 1;

    std::string key;
    std::cout << "\nEnter key: ";
    std::cin >> key;

    if (key.length() < 6) {
        std::cout << "Key cannot be less than 6 characters\n";
        return 1;
    }

    auto *cli         = new CLIProgressIndicator();
    auto *status      = new Status(cli, cmd_args->verbose);
    auto *xrc         = new XorCryptor();
    auto *thread_pool = new ThreadPool();
    int   res = 0, count = 0;
    for (auto &path : *cmd_args->files) {
        count++;
        if (exec_cli_file(cmd_args, "[" + std::to_string(count) + " / " + std::to_string(cmd_args->files->size()) + "] ",
                          path.string(), key, cli, status, xrc, thread_pool)) {
            cli->print_status("Failed to process file: \"" + path.string() + "\"");
            res = 1;
        }
    }
    cli->stop_progress();
    delete cli;
    delete xrc;
    delete status;
    delete thread_pool;

    std::cout << "Completed\n";
    return res;
}

int exec_cli_file(CmdArgs *cmd_args, const std::string &progress, const std::string &file_name, const std::string &key,
                  CLIProgressIndicator *cli, XorCryptor::StatusListener *status, XorCryptor *xrc, ThreadPool *thread_pool) {
    cli->start_progress();

    std::string dest_file_name(file_name);
    bool        res;
    if (cmd_args->verbose) {
        cli->print_status("\nProcessing: " + file_name);
    } else {
        cli->catch_progress(nullptr, 0);
        cli->update_status(progress + " - " + file_name);
    }
    try {
        if (cmd_args->mode == XorCryptor::XrcMode::ENCRYPT) {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) != std::string::npos) {
                cli->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(XorCryptor::FILE_EXTENSION);
            res = xrc->encrypt_file(cmd_args->preserve_src, thread_pool, file_name, dest_file_name, key, status);
        } else {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) == std::string::npos) {
                cli->print_status("This file is not for decryption");
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res            = xrc->decrypt_file(cmd_args->preserve_src, thread_pool, file_name, dest_file_name, key, status);
        }
    } catch (std::exception &e) {
        std::cout << "Unknown error occurred\n";
        std::cout << e.what() << "\n";
        return 1;
    }
    if (res) {
        cli->print_status(progress + (cmd_args->mode == XorCryptor::XrcMode::ENCRYPT ? "Encrypted -> " + dest_file_name : "Decrypted -> " + dest_file_name));
    }
    return !res;
}

void list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files) {
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
                if (entry.is_regular_file()) files->push_back(entry.path());
            }
        } catch (std::exception &e) {
            std::cout << e.what() << "\n";
        }
    }
}

CmdArgs *parse_args(std::vector<std::string> &args) {
    auto *file_args = new std::vector<std::filesystem::path>(),
         *files     = new std::vector<std::filesystem::path>();

    XorCryptor::XrcMode mode         = XorCryptor::XrcMode::INVALID;
    bool                preserve_src = false, recursive = false, verbose = false;
    for (size_t i = 0; i < args.size(); i++) {
        if (args[i] == "-p") preserve_src = true;
        if (args[i] == "-r") recursive = true;
        if (args[i] == "-v") verbose = true;
        if (args[i] == "-e") {
            if (mode != XorCryptor::XrcMode::INVALID) {
                print_error("Multiple modes found. Already defined: Decrypt");
                return nullptr;
            }
            mode = XorCryptor::XrcMode::ENCRYPT;
        }
        if (args[i] == "-d") {
            if (mode != XorCryptor::XrcMode::INVALID) {
                print_error("Multiple modes found. Already defined: Encrypt");
                return nullptr;
            }
            mode = XorCryptor::XrcMode::DECRYPT;
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

    for (auto &path : *file_args) {
        if (std::filesystem::is_regular_file(path)) files->push_back(path);
        if (std::filesystem::is_directory(path)) {
            if (recursive) {
                list_all_files(path, files);
            } else {
                for (const auto &entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_directory()) continue;
                    if (entry.is_regular_file()) files->push_back(entry.path());
                }
            }
        }
    }
    if (files->empty()) {
        print_error("No file(s) found");
        return nullptr;
    }
    return new CmdArgs(files, preserve_src, verbose, mode);
}

void print_help(bool error) {
    std::cout << "\n";
    if (!error) std::cout << "XOR Cryptor\n\n";
    std::cout << "Usage:\n - xor_cryptor [-p] [-r] [-v] -[e/d] -f [files...] [folders...]\n\n";
    std::cout << "Parameters:\n";
    std::cout << "    -p                    - Preserves the source file\n";
    std::cout << "    -r                    - Iterates recursively if any folder found in <files> arg\n";
    std::cout << "    -v                    - Verbose; Prints all the possible stats\n";
    std::cout << "    -e/d                  - encryption/decryption\n";
    std::cout << "    -f <files/folders>... - Encrypts/Decrypts the file(s) mentioned.\n";
}

void print_error(const std::string &error) {
    std::cout << "\nError: " << error << "\n";
    print_help(true);
}
