#ifndef CLI_PROGRESS_INDICATOR
#define CLI_PROGRESS_INDICATOR

#include <string>
#include <thread>

class CLIProgressIndicator {
    std::string mPreIndicatorText;
    bool mRunIndicator = false;

    uint64_t *mProgress = nullptr;
    long double mTotal = 0;

    std::thread *mProgressThread = nullptr;

public:
    void start_progress();

    void stop_progress();

    void print_status(const std::string &status);

    void update_status(const std::string &stat);

    void catch_progress(uint64_t *progress, uint64_t total);
};


#endif //CLI_PROGRESS_INDICATOR
