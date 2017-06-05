# FFXIV Wireshark Dissector

[![Discord](https://img.shields.io/badge/discord-dev%40thebalance-blue.svg)](https://discord.gg/wbtVth5) [![Build Status](https://travis-ci.org/ayyaruq/ffxiv-dissector.svg?branch=master)](https://travis-ci.org/ayyaruq/ffxiv-dissector)

This dissector splits FFXIV frames and reassembles messages to assist in
debugging the FFXIV wire protocol.


### Compilation

To compile the shared library, simply run the following:

    $ mkdir build && cd build
    $ cmake ..
    $ make

To install into `${HOME}/.wireshark/plugins`, run:

    $ make install

For debugging with GDB or LLDB, use `cmake -DCMAKE_BUILD_TYPE=Debug ..` instead.

On Linux and MacOS, you will need to have Wireshark installed with the epan
headers. For building on Windows, I have no idea. Building a static library
is currently possible but I'm terrible at CMake so, good luck.


### TODO

* type matching for battle, market, fishing, etc message types
* heuristic protocol detection (currently uses a giant protocol range)
* unit testing
* more useful filtering
* colourisation


### Help

For feature requests and debugging, please open a GitHub issue and tag
appropriately. For questions about new functionality you'd like to add
or how something in particular works, open an issue or find @acchan#4976
on Discord. If you need help with Wireshark itself, please read upstream
documentation. This dissector is intended to assist developers and shouldn't
be used by the general public for parsing data in realtime or otherwise.


### Contributing

1. Fork it ( https://github.com/ayyaruq/ffxiv-dissector/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
