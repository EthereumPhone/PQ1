#
# Copyright 2019 NXP
# SPDX-License-Identifier: Apache-2.0
#
#

# Create Keys for OPC UA demo
#
# Preconditions
# - open62541 built
#
# Usage example:
# To run using t1oi2c on iMX platform:
# ->python provisionTlsClient.py <rootCA>
#
# To run using jrcpv1:
# ->python open62541Server.py jrcpv1 192.168.1.222:8050 <rootCA>
#
# To run using vcom:
# ->python open62541Server.py vcom COM7 <rootCA>
#
# To run using jrcpv2:
# ->python open62541Server.py jrcpv2 127.0.0.1:8050 <rootCA>
#

import os
import sys
import logging

def usage():
	print("")
	print("Please provide as first argument: CONNECTION_TYPE - vcom, jrcpv1, jrcpv2. Do not specify for \"T1oI2C\"")
	print("Please provide as second argument: CONNECTION_PARAMETER. Default: \"None\"")
	print("Please provide as third argument: ROOT CERTIFICATE. Specify \"none\" for all client certificates to be accepted ")
	print("Usage Example:")
	print("               python %s rootCA" % (__file__,))
	print("               python %s vcom COM5 rootCA" % (__file__,))
	print("               python %s jrcpv1 127.0.0.1:8050 rootCA" % (__file__,))
	print("               python %s jrcpv2 127.0.0.1:8050 rootCA" % (__file__,))
	exit()


def parse_in_args():
	if len(sys.argv) < 2:
		usage();
	else:
		if (sys.argv[1] == 'help'):
			usage();
		elif (sys.argv[1] == 'jrcpv2' or sys.argv[1] == 'jrcpv1'):
			if len(sys.argv) != 4:
				usage();
			connection_type = sys.argv[1]
			connection_data = sys.argv[2]
			port_data = connection_data.split(':')
			JRCP_HOSTNAME = port_data[0]
			try:
				JRCP_PORT = port_data[1]
			except IndexError as exc:
				log.error("Please specify jrcp port.")
				usage();
			os.environ['JRCP_HOSTNAME'] = JRCP_HOSTNAME
			os.environ['JRCP_PORT'] = JRCP_PORT
			print("JRCP_HOSTNAME: %s" % JRCP_HOSTNAME)
			print("JRCP_PORT: %s" % JRCP_PORT)

		elif (sys.argv[1] == 'vcom'):
			if len(sys.argv) != 4:
				usage();
			connection_type = sys.argv[1]
			connection_data = sys.argv[2]
		else:
			if len(sys.argv) != 2:
				usage();
			connection_data = "none"
			connection_type = ""
	return connection_type, connection_data

cur_dir = os.path.abspath(os.path.dirname(__file__))
SERVER_BIN = os.path.join(cur_dir, '..', '..', '..', 'tools', 'open62541_ex_server')
RSA_SERVER_KEY = os.path.join(cur_dir, '..', 'credentials', 'open62541_server_key_pair_ref.pem')
SERVER_CERT = os.path.join(cur_dir, '..', 'credentials', 'open62541_server_cert.der')
#SERVER_CERT = 'NULL'


connection_type, connection_data = parse_in_args()

ROOT_CA = sys.argv[len(sys.argv) - 1]

print(connection_data)
print(connection_type)
print(ROOT_CA)
if ROOT_CA == 'none':
	ROOT_CA = ''
cmd_str = "%s %s %s %s %s" % (SERVER_BIN, SERVER_CERT, RSA_SERVER_KEY, ROOT_CA, connection_data)
print (cmd_str)
os.system(cmd_str)
usage();
