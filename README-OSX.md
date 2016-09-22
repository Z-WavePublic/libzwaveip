Build instructions for OSX
--------------------------
Builds on OSX have been tested with brew packages.

To Compile, make sure you have the necessary packages installed:
```bash
$ brew install cmake openssl doxygen
$ git clone https://github.com/Z-WavePublic/libzwaveip.git
$ cd libzwaveip
$ mkdir build
$ cmake -DOPENSSL_ROOT_DIR=/usr/local/opt/openssl/ -DOPENSSL_LIBRARIES=/usr/local/opt/openssl/lib/ ..
$ make
```

You need to supply the path to the copy of openssl installed with brew, as the default openssl library on OSX is not compatible. 

