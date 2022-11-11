#include "cli.h"

void CLIProgressIndicator::start_progress() {
    if (mProgressThread != nullptr) return;
    mRunIndicator = true;

    mProgressThread = new std::thread([this]() -> void {
        std::vector<std::string> progress_indicator { "-", "\\", "|", "/" };
        int                      idx = 0;
        last_len                     = (int) mPreIndicatorText.length();
        while (mRunIndicator) {
            if (idx == (int) progress_indicator.size()) idx = 0;

            std::cout << "\r" << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << mPreIndicatorText << " " << progress_indicator[idx++];

            int len = (int) mPreIndicatorText.length() + 3;
            if (mProgress != nullptr && mTotal != 0) {
                auto        upper      = std::min((long double) *mProgress, mTotal);
                long double percentage = (upper * 100.0) / mTotal;

                std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
                len += 20;
            }
            last_len = len;

            std::cout.flush();
            std::cout << "\r";
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        std::cout << "\r" << std::string(last_len, ' ') << "\r";
        std::cout.flush();
        std::cout << mPreIndicatorText << "\n";

        thread_complete = true;
        condition.notify_one();
    });
}

void CLIProgressIndicator::print_status(const std::string &status) {
    mTotal = 0;
    std::cout << "\r" << std::string(last_len, ' ') << "\r";
    std::cout.flush();
    std::cout << status << "\n";
}

void CLIProgressIndicator::update_status(const std::string &stat) {
    mPreIndicatorText = stat;
}

void CLIProgressIndicator::catch_progress(uint64_t *progress, uint64_t total) {
    mProgress = progress;
    mTotal    = (long double) total;
}

void CLIProgressIndicator::stop_progress() {
    if (mProgressThread == nullptr) return;

    std::unique_lock<std::mutex> lock(thread_m);
    mRunIndicator = false;
    mProgress     = nullptr;
    mProgressThread->join();
    condition.wait(lock, [this]() -> bool { return thread_complete; });
    mProgressThread = nullptr;
}
