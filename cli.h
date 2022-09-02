#ifndef CLI_PROGRESS_INDICATOR
#define CLI_PROGRESS_INDICATOR

#include <string>
#include <iostream>
#include <iomanip>
#include <unistd.h>
#include <thread>
#include <vector>

class CLIProgressIndicator {
    std::string mPreIndicatorText;
    uint64_t *mProgress = nullptr;
    long double mTotal = 0;
    bool mRunIndicator = false;

public:
    void start_progress();

    void stop_progress();

    static void print_status(const std::string &stat);

    void set_status(std::string stat, long double total);

    void catch_progress(uint64_t *progress);
};


#endif //CLI_PROGRESS_INDICATOR
