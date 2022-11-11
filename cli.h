#ifndef CLI_PROGRESS_INDICATOR

#define CLI_PROGRESS_INDICATOR

#include <atomic>
#include <condition_variable>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

class CLIProgressIndicator {
    std::string       mPreIndicatorText;
    std::atomic<bool> mRunIndicator = false;

    uint64_t   *mProgress = nullptr;
    long double mTotal    = 0;
    int         last_len  = 0;

    std::mutex              thread_m;
    std::condition_variable condition;
    std::atomic<bool>       thread_complete = false;
    std::thread            *mProgressThread = nullptr;

public:
    void start_progress();

    void stop_progress();

    void print_status(const std::string &status);

    void update_status(const std::string &stat);

    void catch_progress(uint64_t *progress, uint64_t total);
};

#endif    // CLI_PROGRESS_INDICATOR
