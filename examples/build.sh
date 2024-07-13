#!/bin/bash
g++ $1 -L../lib -lTcpClient -lssl -lcrypto
