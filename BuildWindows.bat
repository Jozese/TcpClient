@echo off

cl /c /I %1 /EHsc /MT src\TcpClient.cpp

lib /out:lib\libTcpClient.lib TcpClient.obj

del TcpClient.obj