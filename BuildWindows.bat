@echo off
cl /c src\TcpClient.cpp /I %1

lib /out:lib\libTcpClient.lib TcpClient.obj

del TcpClient.obj