#include "cli.h"

void CLIProgressIndicator::start_progress() {
    std::thread indicator_thread([this]() -> void {
        std::vector<std::string> progress_indicator{"-", "\\", "|", "/", "-"};
        int idx = 0, last_len = (int) mPreIndicatorText.length();
        while (idx != -1) {
            if (idx == (int) progress_indicator.size()) idx = 0;

            int len = 0;
            std::cout.flush();
            std::cout << std::string(last_len, ' ') << "\r";
            std::cout.flush();
            std::cout << mPreIndicatorText << " " << progress_indicator[idx++];
            len += (int) mPreIndicatorText.length() + 3;
            if (mTotal != 0) {
                float percentage = (mProgress * 100.0) / mTotal;
                std::cout << " [ " << std::fixed << std::setprecision(2) << percentage << " / 100 ]";
                len += 20;
            }
            last_len = len;
            std::cout << "\r";
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    });
    indicator_thread.detach();
}

void CLIProgressIndicator::print_status(const std::string &stat) {
    std::cout << stat << "\n";
}

void CLIProgressIndicator::set_status(std::string stat, long double t) {
    mPreIndicatorText = std::move(stat);
    mTotal = t;
}

void CLIProgressIndicator::set_progress(long double progress) {
    mProgress = progress;
}
