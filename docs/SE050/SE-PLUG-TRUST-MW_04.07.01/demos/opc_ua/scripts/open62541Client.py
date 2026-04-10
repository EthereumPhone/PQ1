#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Start open62541 server
#
# Preconditions
# - open62541 client built
#
# Usage example:
# To run :
# ->python open62541Client.py opc.tcp://<SERVER_IP>:<SERVER_PORT>
#
#

import os
import sys
import logging

def usage():
	print("")
	print("Please provide as first argument:  <OPC UA SERVER ADDRESS>")
	print("Usage Example:")
	print("               python %s opc.tcp://127.0.0.1:4840" % (__file__,))

cur_dir = os.path.abspath(os.path.dirname(__file__))
CLIENT_BIN = os.path.join(cur_dir, '..', '..', '..', 'tools', 'open62541_ex_client')
RSA_CLIENT_KEY = os.path.join(cur_dir, '..', 'credentials', 'open62541_client_key_pair.pem')
CLIENT_CERT = os.path.join(cur_dir, '..', 'credentials', 'open62541_client_cert.der')
connection_data = ''

if len(sys.argv) == 1:
	usage();
else:
	if (sys.argv[1] == 'help'):
		usage();
	else:
		connection_data = sys.argv[1]
		cmd_str = "%s -cert %s -key %s -securityMode 3 -securityPolicy http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256 %s" % (CLIENT_BIN, CLIENT_CERT, RSA_CLIENT_KEY, connection_data)
		print (cmd_str)
		os.system(cmd_str)
