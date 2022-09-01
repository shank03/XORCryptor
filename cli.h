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
    long double mProgress = 0, mTotal = 0;

public:
    void start_progress();

    static void print_status(const std::string &stat);

    void set_status(std::string stat, long double total);

    void set_progress(long double progress);
};


#endif //CLI_PROGRESS_INDICATOR
