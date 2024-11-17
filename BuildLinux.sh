#!/bin/bash

g++ -c src/TcpClient.cpp --std=c++17
ar crf lib/libTcpClient.a TcpClient.o
rm TcpClient.o
cp lib/libTcpClient.a /usr/local/lib
cp lib/libTcpClient.a /usr/lib
cp -r include/TcpClient /usr/local/include
cp -r include/TcpClient /usr/include