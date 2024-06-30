#!/bin/bash

g++ -c src/TcpClient.cpp
ar crf lib/libTcpClient.a TcpClient.o
rm TcpClient.o