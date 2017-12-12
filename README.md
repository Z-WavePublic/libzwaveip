libzwaveip - Control Z-Wave devices from your IP network
========================================================

libzwaveip makes it easy to control Z-Wave devices from your IP network via a Z/IP Gateway. A Z/IP Gateway binary for Raspberry Pi is available here: [http://zwavepublic.com/developer](http://zwavepublic.com/developer).

Questions? Please use the discussion forum at [http://forum.z-wavepublic.com/](http://forum.z-wavepublic.com/).

Example applications
--------------------
Two example applications are provided: reference_client and reference_listener. The reference_client is
a command line client for adding, removing and sending commands to Z-Wave nodes. The Z-Wave listener
listens for notifications from the Z-Wave network. When a notification arrives it is decoded and pretty-printed.

Build instructions for Raspberry Pi
-----------------------------------
To get started quickly, use we recommend that you use the Raspberry Pi image we have prepared. Follow these instructions to build the libzwaveip reference_client and reference_listener:

0. Prepare the Raspberry Pi SD image according to the instructions at [www.zwavepublic.com/developer](http://www.zwavepublic.com/developer)
0. SSH into the Raspberry Pi
0. Run the following commands:
```bash
$ sudo apt-get update
$ sudo apt-get install cmake libssl1.0-dev libavahi-client-dev libxml2-dev libbsd-dev libncurses5-dev git
$ git clone https://github.com/Z-WavePublic/libzwaveip.git
$ cd libzwaveip
$ mkdir build
$ cd build
$ cmake ..
$ make
```

To test the reference_client, make sure the zipgateway is running and connect to it:

    $ ./reference_client -s <IP of ZIP Gateway>

See section "Working with the Reference Z/IP client" in [this guide](http://zwavepublic.com/developer)
for instructions on using the reference_client.

