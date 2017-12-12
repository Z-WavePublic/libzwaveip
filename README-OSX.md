Build instructions for macOS
----------------------------

Builds on macOS have been tested with Homebrew packages.

**CMake:**

The recommended way of building libzwaveip and the example applications for macOS is using CMake. Building with CMake requires that you provide the dependencies yourself. The supported method of doing this is with [Homebrew](http://brew.sh/). Once you have Homebrew installed, you can download all the required libraries with this command:

```bash
$ brew install cmake openssl doxygen
```

Once you have the dependencies installed, you can build the project using CMake with the following commands (from inside the project’s directory):

```bash
$ mkdir build
$ cd build
$ cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl/ -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib/ ..
$ make
```

Make sure to supply the paths to the OpenSSL installed with Homebrew to CMake.

**Xcode:**

As a convenience for developers on macOS, an Xcode Project is also provided. The requirement for an OpenSSL installed with Homebrew remains, so make sure it is installed before attempting to build the project:

```bash
$ brew install openssl
```

The Xcode Project provides two shared schemes: **’reference\_client’** and **’reference\_listener’** that build the example applications. Sample default command line arguments are provided for them. Don’t modify these schemes to fit your development environment - duplicate them as non-shared schemes and modify these copies instead (the shared schemes can also be hidden from the jump bar to avoid confusion).
