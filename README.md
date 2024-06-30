# TCP Client for C++

Simple TCP over TLS implementation using [OpenSSL](https://github.com/openssl) for both Windows and Linux.

## Usage
Check out the [examples](examples) folder for usage examples.

## Building
### Linux
1. **Install OpenSSL**
```bash
sudo apt-get install libssl-dev
```
2. **Run BuildLinux.sh**
```bash
./BuildLinux.sh
```
Compiled static library will be in [lib](lib)
### Windows (Visual Studio)
1. **Install OpenSSL**

You can use a package manager to download and install 
OpenSSL like [vcpkg](https://vcpkg.io/en/) or directly clone it from [OpenSSL](https://github.com/openssl) repository and build it yourself.

```bash
vcpkg install openssl:x64-windows
```

2. **Run BuildWindows.bat**

Open the developer command prompt for Visual Studio and run the script specifying OpenSSL include path.

```bash
BuildWindows.bat "path/to/openssl/include"
```
Again, compiled static library will be inside [lib](lib)


