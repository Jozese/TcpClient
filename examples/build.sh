#!/bin/bash
g++ $1 -L../lib -lTcpClient -lssl -lcrypto --std=c++17
