#ifndef CLI_H
#define CLI_H

#include <string>
#include <iostream>
#include <unistd.h>
#include <thread>

class CLI {
    std::string mPreIndicatorText;
    long double mProgress = 0, mTotal = 0;

    void start_progress();

public:
    static void print_status(const std::string &stat);

    void set_status(std::string stat, long double total);

    void set_progress(long double progress);

    int exec_cli(int mode, std::string &file_name, std::string &key);
};


#endif //CLI_H
