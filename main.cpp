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

int      exec_cli_file(CmdArgs *cmd_args, const std::string &progress, const std::filesystem::path &file_path, const std::string &key,
                       CLIProgressIndicator *cli, XorCryptor::StatusListener *status, XorCryptor *xrc);
void     list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files, XorCryptor::XrcMode &mode);
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
    for (int i = 1; i < argc; i++) {
        args[i - 1] = std::string(argv[i]);
        if (args[i - 1] == "-h" || args[i - 1] == "--help") {
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

    auto *cli    = new CLIProgressIndicator();
    auto *status = new Status(cli, cmd_args->verbose);
    auto *xrc    = new XorCryptor();
    cli->start_progress();

    size_t                  max_jobs = std::thread::hardware_concurrency(), total_jobs = cmd_args->files->size();
    auto                   *workers     = new std::vector<std::thread *>(total_jobs, nullptr);
    std::atomic<size_t>     queued_jobs = 0, completed_jobs = 0;
    std::mutex              hold_mutex, term_mutex;
    std::condition_variable hold_cv, term_cv;

    int res = 0, count = 0;
    for (size_t i = 0; i < total_jobs; i++) {
        if (queued_jobs == max_jobs) {
            std::unique_lock<std::mutex> hold_lock(hold_mutex);
            hold_cv.wait(hold_lock, [&]() -> bool { return queued_jobs != max_jobs; });
        }

        queued_jobs++;
        count++;
        (*workers)[i] = new std::thread(
                [&queued_jobs, &hold_cv, &completed_jobs, &term_cv,
                 &cmd_args, &key](int count, int *res, const std::filesystem::path &path,
                                  CLIProgressIndicator *cli, Status *status, XorCryptor *xrc) -> void {
                    if (exec_cli_file(cmd_args, "[" + std::to_string(count) + " / " + std::to_string(cmd_args->files->size()) + "] ",
                                      path, key, cli, status, xrc)) {
                        *res = 1;
                    }

                    queued_jobs--;
                    hold_cv.notify_one();
                    completed_jobs++;
                    term_cv.notify_one();
                },
                count, &res, (*cmd_args->files)[i], cli, status, xrc);
    }
    for (auto &t : *workers) t->join();

    cli->print_status("All jobs queued");
    std::unique_lock<std::mutex> term_lock(term_mutex);
    term_cv.wait(term_lock, [&]() -> bool { return completed_jobs == total_jobs; });

    cli->stop_progress();
    delete cli;
    delete xrc;
    delete status;
    delete workers;

    std::cout << (cmd_args->mode == XorCryptor::ENCRYPT ? "Encryption Completed\n" : "Decryption Completed\n");
    return res;
}

int exec_cli_file(CmdArgs *cmd_args, const std::string &progress, const std::filesystem::path &file_path, const std::string &key,
                  CLIProgressIndicator *cli, XorCryptor::StatusListener *status, XorCryptor *xrc) {
    std::string file_name = file_path.string();
    std::string dest_file_name(file_name);
    bool        res;

    auto parent     = file_path.parent_path().parent_path().string();
    auto short_path = file_path.string().replace(0, parent.length(), "...");
    if (cmd_args->verbose) {
        cli->print_status("\nProcessing: " + short_path);
    } else {
        cli->catch_progress(nullptr, 0);
        cli->update_status(progress + " - " + short_path);
    }
    try {
        if (cmd_args->mode == XorCryptor::XrcMode::ENCRYPT) {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) != std::string::npos) {
                cli->print_status("This file is not for encryption");
                return 1;
            }
            dest_file_name.append(XorCryptor::FILE_EXTENSION);
            res = xrc->encrypt_file(cmd_args->preserve_src, file_name, dest_file_name, key, status);
        } else {
            if (dest_file_name.find(XorCryptor::FILE_EXTENSION) == std::string::npos) {
                cli->print_status("This file is not for decryption");
                return 1;
            }
            dest_file_name = dest_file_name.substr(0, dest_file_name.length() - 4);
            res            = xrc->decrypt_file(cmd_args->preserve_src, file_name, dest_file_name, key, status);
        }
    } catch (std::exception &e) {
        std::cout << file_name + " == Error: " + std::string(e.what()) + "\n";
        return 1;
    }
    if (res) {
        if (cmd_args->verbose) cli->print_status(progress + (cmd_args->mode == XorCryptor::XrcMode::ENCRYPT ? "Encrypted -> " + dest_file_name : "Decrypted -> " + dest_file_name));
    }
    return !res;
}

void list_all_files(std::filesystem::path &root_path, std::vector<std::filesystem::path> *files, XorCryptor::XrcMode &mode) {
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
                    if (mode == XorCryptor::XrcMode::DECRYPT && entry.path().extension() == ".xrc") files->push_back(entry.path());
                    if (mode == XorCryptor::XrcMode::ENCRYPT && entry.path().extension() != ".xrc") files->push_back(entry.path());
                }
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

    std::cout << "Retrieving files ...\n";
    for (auto &path : *file_args) {
        if (std::filesystem::is_regular_file(path)) {
            if (mode == XorCryptor::XrcMode::DECRYPT && path.extension() == ".xrc") files->push_back(path);
            if (mode == XorCryptor::XrcMode::ENCRYPT && path.extension() != ".xrc") files->push_back(path);
        }
        if (std::filesystem::is_directory(path)) {
            if (recursive) {
                list_all_files(path, files, mode);
            } else {
                for (const auto &entry : std::filesystem::directory_iterator(path)) {
                    if (entry.is_directory()) continue;
                    if (entry.is_regular_file()) {
                        if (mode == XorCryptor::XrcMode::DECRYPT && entry.path().extension() == ".xrc") files->push_back(entry.path());
                        if (mode == XorCryptor::XrcMode::ENCRYPT && entry.path().extension() != ".xrc") files->push_back(entry.path());
                    }
                }
            }
        }
    }
    if (files->empty()) {
        print_error("No " + std::string(mode == XorCryptor::XrcMode::DECRYPT ? ".xrc " : "") + "file(s) found");
        return nullptr;
    }
    std::cout << files->size() << (mode == XorCryptor::XrcMode::DECRYPT ? " .xrc" : "") << " file(s) found\n";
    return new CmdArgs(files, preserve_src, verbose, mode);
}

void print_help(bool error) {
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
