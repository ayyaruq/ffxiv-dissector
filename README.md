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
headers. Building a static library
is currently possible but I'm terrible at CMake so, good luck.


### On Windows

Follow instructions in [this guide](https://www.wireshark.org/docs/wsdg_html_chunked/ChSetupWin32.html) up to Step 2.2.9. For Step 2.2.9, ignore what's written there. Instead, download the wireshark 2.2.7 source code and extract to wireshark base directory (C:\Development in the guide). You may need to download 7-Zip.
        
    > wget https://1.na.dl.wireshark.org/src/wireshark-2.2.7.tar.bz2
    > 7z x wireshark-2.2.7.tar.bz2
    > 7z x wireshark-2.2.7.tar -oC:\Development
    > move C:\Development\wireshark-2.2.7 C:\Development\wireshark
    > del wireshark-2.2.7.tar.bz2

**External Library**

Follow steps up to 2.2.12.

With either with the same command prompt or a new Visual Studio command prompt (after re-doing everything in 2.2.10),
execute the following commands

    > git clone https://github.com/ayyaruq/ffxiv-dissector
    > cd ffxiv-dissector && mkdir build && cd build
    > cmake .. -DWIRESHARK_INCLUDE_DIRS=%WIRESHARK_BASE_DIR%\wireshark;%WIRESHARK_BASE_DIR%\wsbuild64;%WIRESHARK_BASE_DIR%\Wireshark-win64-libs-2.2\WPdpack\include -DGLIB2_INCLUDE_DIRS=%WIRESHARK_BASE_DIR%\Wireshark-win64-libs-2.2\gtk2\include\glib-2.0;%WIRESHARK_BASE_DIR%\Wireshark-win64-libs-2.2\gtk2\lib\glib-2.0\include -DGCRYPT_INCLUDE_DIR=%WIRESHARK_BASE_DIR%\Wireshark-win64-libs-2.2\gnutls-3.2.15-2.9-win64ws\include -G "Visual Studio 12 Win64" -DEXTRA_LIB_DIRS=%WIRESHARK_BASE_DIR%\wsbuild64\run\RelWithDebInfo;%WIRESHARK_BASE_DIR%\Wireshark-win64-libs-2.2\gtk2\lib
    > msbuild /p:Configuration=Release ffxiv.vcxproj
    > msbuild INSTALL.vcxproj

If 32-bit architecture then replace 3rd line with

    cmake .. -DWIRESHARK_INCLUDE_DIRS=%WIRESHARK_BASE_DIR%\wireshark;%WIRESHARK_BASE_DIR%\wsbuild32;%WIRESHARK_BASE_DIR%\Wireshark-win32-libs-2.2\WPdpack\include -DGLIB2_INCLUDE_DIRS=%WIRESHARK_BASE_DIR%\Wireshark-win32-libs-2.2\gtk2\include\glib-2.0;%WIRESHARK_BASE_DIR%\Wireshark-win32-libs-2.2\gtk2\lib\glib-2.0\include -DGCRYPT_INCLUDE_DIR=%WIRESHARK_BASE_DIR%\Wireshark-win32-libs-2.2\gnutls-3.2.15-2.9-win32ws\include -G "Visual Studio 12" -DEXTRA_LIB_DIRS=%WIRESHARK_BASE_DIR%\wsbuild32\run\RelWithDebInfo;%WIRESHARK_BASE_DIR%\Wireshark-win32-libs-2.2\gtk2\lib

**Built-in Plugin**

Get ffxiv-dissector source code and copy to wireshark source tree.

    > cd C:\Development\
    > git clone https://github.com/ayyaruq/ffxiv-dissector
    > cd ffxiv-dissector/src
    > copy CMakeListsCustom.txt packet* C:\Development\wireshark\epan\dissectors

Follow steps 2.2.10-2.2.12 in the guide.

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
