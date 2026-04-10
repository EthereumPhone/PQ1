/* Copyright 2019 NXP
 *
 * This software is owned or controlled by NXP and may only be used
 * strictly in accordance with the applicable license terms.  By expressly
 * accepting such terms or by downloading, installing, activating and/or
 * otherwise using the software, you are agreeing that you have read, and
 * that you agree to comply with and are bound by, such license terms.  If
 * you do not agree to be bound by the applicable license terms, then you
 * may not retain, install, activate or otherwise use the software.
 */

#include "JrcpTcpServer.h"

#include <iostream>
#include <string>


using namespace std;

static void usage(string name)
{
	cout << "Usage: " << name << "\n  -h,--help\n"  << "  -c,--Com  VCOM Port \n\n" <<
		"  example : " << name << " -c COM3\n";
}

int main(int argc, char *argv[])
{
	char *port = "8050";
	//char *ipaddress = "127.0.0.1";
	int iResult = 0;
	char *progname = argv[0];
	char *VComPort = argv[2];
	bool close = TRUE;
	if (argc < 2) {

		usage(progname);
		return 1;
	}
	for (int i = 1; i < argc; i++) {
		string arg = argv[i];
		if ((arg == "-h") || (arg == "--help")) {
			usage(progname);
			return 0;
		}
		else if ((arg == "-c") || (arg == "--Com")) {
			VComPort = argv[++i];
		}
		if ((arg == "-e") || (arg == "--coe")) {
			string coe = argv[++i];
			if(coe == "FALSE"){
				close = FALSE;
			}
		}
	}
restart:
	JrcpTcpServer server(port, VComPort);
	server.listenAndConnect();
	server.closeOnExit(close);
	// Receive until the peer shuts down the connection
	do {
		iResult = server.doTranscieve();
        if (iResult == 2) {
            server.disconnect();
            goto restart;
        }
	} while (iResult == 0);

	server.disconnect();

	printf("Enter any key to exit");
	getchar();
    return 0;
}
