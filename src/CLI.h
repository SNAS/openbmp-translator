/*
 * Copyright (c) 2013-2016 Cisco Systems, Inc. and others.  All rights reserved.
 * Copyright (c) 2019 Lumin Shi.  All rights reserved.
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v1.0 which accompanies this distribution,
 * and is available at http://www.eclipse.org/legal/epl-v10.html
 *
 */

#ifndef OBMPV2_TRANSLATOR_CLI_H
#define OBMPV2_TRANSLATOR_CLI_H

#include <iostream>
#include <cstring>
#include "Config.h"

using namespace std;

class CLI {
public:
    /**
     * Parse and handle the command line args
     *
     * \param [out] cfg    Reference to config options - Will be updated based on cli
     *
     * \returns true if error, false if no error
     *
     */
    static bool ReadCmdArgs(int argc, char **argv, Config *cfg) {

        if (argc > 1 and !strcmp(argv[1], "-h")) {
            Usage(argv[0]);
            exit(0);
        }

        // Loop through the args
        for (int i = 1; i < argc; i++) {
            // Make sure we have the correct number of required args
            if (argc > 1 and !strcmp(argv[1], "-v")) {   // Version
                cout << "openbmp_v2 translator version : " << 0.1 << endl;
                exit(0);
            }
            else if (!strcmp(argv[i], "-h")) {   // Help message
                Usage(argv[0]);
                exit(0);
            }
            else if (!strcmp(argv[i], "-c")) {  // Config filename
                // We expect the next arg to be the filename
                if (i + 1 >= argc) {
                    cout << "INVALID ARG: -c expects the filename to be specified" << endl;
                    return true;
                }

                // Set the new filename
                cfg->cfg_filename = argv[++i];
            }

        }

        return false;
    }


private:
    /**
     * Usage of the program
     */
    static void Usage(char *prog) {
        cout << "Usage: " << prog << " -c <filename> <options>" << endl;

        cout << endl << "  OTHER OPTIONS:" << endl;
        cout << "     -v                   Version" << endl;
        cout << "     -h                   Help" << endl;

        cout << endl;
    }
};
#endif //OBMPV2_TRANSLATOR_CLI_H
