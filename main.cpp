#include <iostream>
#include <queue>

#include "cli.h"
#include "xor_cryptor.h"

void print_help(bool error = false) {
    std::cout << "\n";
    if (!error) std::cout << "XOR Cryptor\n\n";
    std::cout << "Usage:\n - xor_cryptor [-p] [-r] [-v] -m [e/d] -f [files...] [folders...]\n\n";
    std::cout << "Parameters:\n";
    std::cout << "    -p                    - Preserves the source file\n";
    std::cout << "    -r                    - Iterates recursively if any folder found in <files> arg\n";
    std::cout << "    -v                    - Verbose; Prints all the possible stats\n";
    std::cout << "    -m <mode>             - mode is either 'e' (encryption) or 'd' (decryption)\n";
    std::cout << "    -f <files/folders>... - Encrypts/Decrypts the file(s) mentioned.\n";
}

struct Status : XorCryptor::StatusListener {
    CLIProgressIndicator *progressIndicator;
    bool                  verbose;

    explicit Status(CLIProgressIndicator *indicator, bool verbose) : progressIndicator(indicator),
                                                                     verbose(verbose) {}

    void print_status(const std::string &status) override {
        if (verbose) {
            progressIndicator->print_status(status);
        }
    }

    void catch_progress(const std::string &status, uint64_t *progress_ptr, uint64_t total) override {
        if (verbose) {
            progressIndicator->update_status(status);
            progressIndicator->catch_progress(progress_ptr, total);
        }
    }
};

int exec_cli_file(int mode, bool preserve_src, bool verbose, const std::string &progress, const std::string &file_name, const std::string &key,
                  CLIProgressIndicator *cli, XorCryptor::StatusListener *status, XorCryptor *xrc, ThreadPool *thread_pool) {
    cli->start_progress();

    std::string dest_file_name(file_name);
    bool        res;
    if (verbose) {
        cli->print_status("\nProcessing: " + file_name);
    } else {
        cli->catch_progress(nullptr, 0);
        cli->update_status(progress + " - " + file_name);
    }
    try {
        if (mode) {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) != std::string::npos) {
                cli->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(XorCryptor::FILE_EXTENSION);
            res = xrc->encrypt_file(preserve_src, thread_pool, file_name, dest_file_name, key, status);
        } else {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) == std::string::npos) {
                cli->print_status("This file is not for decryption");
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res            = xrc->decrypt_file(preserve_src, thread_pool, file_name, dest_file_name, key, status);
        }
    } catch (std::exception &e) {
        std::cout << "Unknown error occurred\n";
        std::cout << e.what() << "\n";
        return 1;
    }
    if (res) {
        if (verbose) cli->print_status(progress + (mode ? "Encrypted -> " + dest_file_name : "Decrypted -> " + dest_file_name));
    }
    return !res;
}

void print_error(const std::string &error) {
    std::cout << "\nError: " << error << "\n";
    print_help(true);
}

void list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files) {
    std::queue<std::filesystem::path> q;
    q.push(root_path);
    while (!q.empty()) {
        std::filesystem::path path = q.front();
        q.pop();

        try {
            for (const auto &entry : std::filesystem::directory_iterator(path)) {
                if (entry.is_directory()) {
                    q.push(entry.path());
                    continue;
                }
                if (entry.is_regular_file()) files->push_back(entry.path());
            }
        } catch (std::exception &e) {
            std::cout << e.what() << "\n";
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc == 1) {
        print_help();
        return 0;
    }

    std::vector<std::string> args(argc);
    for (int i = 1; i < argc; i++) args[i] = std::string(argv[i]);

    std::vector<std::filesystem::path> files_args, final_files;
    int                                mode          = 1;    // default: Encryption mode
    bool                               has_help      = false;
    bool                               preserve_src  = false;
    bool                               itr_recursive = false;
    bool                               verbose       = false;
    for (int i = 0; i < argc; i++) {
        if (args[i] == "-p") preserve_src = true;
        if (args[i] == "-r") itr_recursive = true;
        if (args[i] == "-v") verbose = true;
        if (args[i] == "-h" || args[i] == "--help") {
            has_help = true;
            break;
        }
        if (args[i] == "-m") {
            if (i + 1 >= argc) continue;
            if (args[i + 1] == "e") {
                mode = 1;
            } else if (args[i + 1] == "d") {
                mode = 0;
            } else {
                print_error("Invalid mode");
                return 1;
            }
        } else if (args[i] == "-f") {
            if (i + 1 >= argc) {
                print_error("No file(s) specified");
                return 1;
            }
            i++;
            while (i < argc && args[i][0] != '-') files_args.emplace_back(args[i++]);
        }
    }

    if (has_help) {
        print_help();
        return 0;
    }

    if (files_args.empty()) {
        print_error("No file(s) specified");
        return 1;
    }

    for (auto &path : files_args) {
        if (std::filesystem::is_regular_file(path)) final_files.push_back(path);
        if (std::filesystem::is_directory(path)) {
            std::cout << "Retrieving files from " << path << " ...\n";
            if (itr_recursive) {
                list_all_files(path, &final_files);
            } else {
                for (const auto &entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_directory()) continue;
                    if (entry.is_regular_file()) final_files.push_back(entry.path());
                }
            }
        }
    }
    if (final_files.empty()) {
        print_error("No file(s) found");
        return 1;
    }
    std::cout << "Total files: " << final_files.size() << "\n";

    std::string key;
    std::cout << "\nEnter key: ";
    std::cin >> key;

    if (key.length() < 6) {
        std::cout << "Key cannot be less than 6 characters\n";
        return 1;
    }

    auto *cli         = new CLIProgressIndicator();
    auto *status      = new Status(cli, verbose);
    auto *xrc         = new XorCryptor();
    auto *thread_pool = new ThreadPool();
    int   res = 0, count = 0;
    for (auto &path : final_files) {
        count++;
        if (exec_cli_file(mode, preserve_src, verbose, "[" + std::to_string(count) + " / " + std::to_string(final_files.size()) + "] ",
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
