@echo off
cl /c src\TcpClient.cpp

lib /out:lib\libTcpClient.lib TcpClient.obj

del TcpClient.obj