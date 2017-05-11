# FFXIV Wireshark Dissector

This dissector splits FFXIV frames and reassembles messages to assist in
debugging the FFXIV wire protocol.


### Compilation

To compile the shared library, simply run the following:

    $ mkdir build && cd build
    $ cmake ..
    $ make

To install into `${HOME}/.wireshark/plugins`, run:

    $ make install

On MacOS, you will need to have Wireshark installed with the epan headers.
For building on Windows or Linux, I have no idea. Building a static library
is currently possible but I'm terrible at CMake so, good luck.


### TODO

* deal with frames spread over multiple packets
* blocks spread across multiple frames, RIP
* heuristic application
* unit testing
* more useful filtering
* colourisation
* type matching for battle, market, fishing, etc message types


### Contributing

1. Fork it ( https://github.com/[my-github-username]/ffxiv-dissector/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
