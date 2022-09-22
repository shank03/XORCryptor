#include "cli.h"

#include <iomanip>
#include <iostream>
#include <vector>

void CLIProgressIndicator::start_progress() {
    if (mProgressThread != nullptr) return;
    mRunIndicator = true;

    mProgressThread = new std::thread([this]() -> void {
        std::vector<std::string> progress_indicator { "-", "\\", "|", "/" };
        int                      idx = 0, last_len = (int) mPreIndicatorText.length();
        while (mRunIndicator) {
            if (idx == (int) progress_indicator.size()) idx = 0;

            std::cout << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << mPreIndicatorText << " " << progress_indicator[idx++];

            int len = (int) mPreIndicatorText.length() + 3;
            if (mProgress != nullptr && mTotal != 0) {
                len += 20;

                long double upper      = *mProgress;
                upper                  = std::min(upper, mTotal);
                long double percentage = (upper * 100.0) / mTotal;

                std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
            }
            last_len = len;

            std::cout.flush();
            std::cout << "\r";
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
        }
        if (mProgressThread != nullptr && mProgressThread->joinable()) mProgressThread->join();
        mProgressThread = nullptr;
    });
    mProgressThread->detach();
}

void CLIProgressIndicator::print_status(const std::string &status) {
    mTotal = 0;
    std::cout << std::string(40, ' ') << "\r";
    std::cout.flush();
    std::cout << status << "\n";
}

void CLIProgressIndicator::update_status(const std::string &stat) {
    mPreIndicatorText = stat;
}

void CLIProgressIndicator::catch_progress(uint64_t *progress, long double total) {
    mProgress = progress;
    mTotal    = total;
}

void CLIProgressIndicator::stop_progress() {
    mRunIndicator = false;
    mProgress     = nullptr;
    while (mProgressThread != nullptr)
        ;
}
