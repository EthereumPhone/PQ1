#
# Copyright 2021,2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

CC=gcc # gcc || clang
CCOPTIONS=-std=c11 -Wall -Wextra -pedantic -Wstrict-overflow -fno-strict-aliasing -g -MMD -MP -lpthread

SSLPATH=-L/openssl
INCLUDEDIR=-I../common/ -I/usr/local_azure/include/ -I../common/libjwt

all: azure_imx_register azure_imx_connect

azure_imx_register: azure_imx_register.c Makefile
	$(CC) $(CCOPTIONS) $(SSLPATH) azure_imx_register.c mqtt_azure.c $(INCLUDEDIR) $(BUILDARGS)  -ljwt -lcrypto -lssl -lpaho-mqtt3cs -L/usr/local_azure/lib/ -ljansson -o azure_imx_register

azure_imx_connect: azure_imx_connect.c Makefile
	$(CC) $(CCOPTIONS) $(SSLPATH) azure_imx_connect.c mqtt_azure.c $(INCLUDEDIR) $(BUILDARGS)  -ljwt -lcrypto -lssl -lpaho-mqtt3cs -L/usr/local_azure/lib/ -ljansson -o azure_imx_connect

clean:
	-rm azure_imx_connect azure_imx_register *.d

.PHONY: all
