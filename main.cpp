/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#include "CLI.h"
#include "Logger.h"
#include "Translator.h"
#include <csignal>
#include <iostream>
#include <unistd.h>
#include <sys/stat.h>
#include <fstream>

using namespace std;

// Global pointers
// needs logger to make logger macros (defined in Logger.h) work, e.g., LOG_NOTICE.
static Logger *logger;
static Translator *translator;

// termination signal handling
static void sigterm (int sig) {
    LOG_INFO("Termination signal received %d", sig);
    translator->stop();
}

/**
 * Daemonize the program
 */
void daemonize(const char *pid_filename) {
    pid_t pid, sid;

    pid = fork();

    if (pid < 0) // Error forking
        _exit(EXIT_FAILURE);

    if (pid > 0) {
        _exit(EXIT_SUCCESS);

    } else {
        sid = setsid();
        if (sid < 0)
            exit(EXIT_FAILURE);
    }

    //Change File Mask
    umask(0);

    //Change Directory
    if ((chdir("/")) < 0)
        exit(EXIT_FAILURE);

    //Close Standard File Descriptors
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    // Write PID to PID file if requested
    if (pid_filename != nullptr) {
        pid = getpid();
        ofstream pfile(pid_filename);

        if (pfile.is_open()) {
            pfile << pid << endl;
            pfile.close();
        } else {
            LOG_ERR("Failed to write PID to %s", pid_filename);
            exit(EXIT_FAILURE);
        }
    }
}

int main(int argc, char **argv) {
    // Initialize Config (singleton)
    auto *config = Config::init();

    // Process CLI args
    if (CLI::ReadCmdArgs(argc, argv, config)) {
        return 1;
    }

    // Load config file
    if (config->cfg_filename != nullptr) {
        try {
            config->load_config_file();
        } catch (char const *str) {
            cout << "ERROR: Failed to load the configuration file: " << str << endl;
            return 2;
        }
    } else {
        cout << "ERROR: Must specify the path to configuration file: " << endl;
        return 2;
    }

    // init logger
    logger = Logger::init(nullptr, nullptr);
    // init message bus
    MessageBus::init();

    signal(SIGINT, sigterm);
    signal(SIGTERM, sigterm);

    translator = new Translator();
    translator->start();

    // termination signal received, now we clean up.
    delete translator;

    return 0;
}
