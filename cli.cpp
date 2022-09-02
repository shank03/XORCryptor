#include "cli.h"

void CLIProgressIndicator::start_progress() {
    mRunIndicator = true;
    std::thread([this]() -> void {
        std::vector<std::string> progress_indicator{"-", "\\", "|", "/", "-"};
        int idx = 0, last_len = (int) mPreIndicatorText.length();
        while (mRunIndicator) {
            if (idx == (int) progress_indicator.size()) idx = 0;

            int len = 0;
            std::cout.flush();
            std::cout << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << mPreIndicatorText << " " << progress_indicator[idx++];
            len += (int) mPreIndicatorText.length() + 3;
            if (mProgress != nullptr && mTotal != 0) {
                long double upper = *mProgress;
                upper = std::min(upper, mTotal);
                long double percentage = (upper * 100.0) / mTotal;
                std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
                len += 20;
            }
            last_len = len;
            std::cout << "\r";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::terminate();
    }).detach();
}

void CLIProgressIndicator::print_status(const std::string &stat) {
    std::cout << stat << "\n";
}

void CLIProgressIndicator::set_status(std::string stat, long double t) {
    mPreIndicatorText = std::move(stat);
    mTotal = t;
}

void CLIProgressIndicator::catch_progress(uint64_t *progress) {
    mProgress = progress;
}

void CLIProgressIndicator::stop_progress() {
    mProgress = nullptr;
    mRunIndicator = false;
}
