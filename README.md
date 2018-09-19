# Mikrotik Winbox Protocol Dissector for Wireshark
*Note: This only works on "non-secure" sessions as specified by the client*

---
## Installation is Simple
* LUA-based dissector, no recompilation necessary
* Drop the `Winbox_Dissector.lua` file into your `/$HOME/.wireshark/plugins` folder.

---
## Usage
By default, any TCP traffic to/from TCP port 8291 will be decoded as Winbox traffic once the dissector is installed.

While a single message from the client/server to its destination would be preferable for
parsing purposes. This is not always the case, observing live communications proved that
there are many ways that Winbox Messages can be formatted and sent.

Below is an example of a Winbox communications capture that has the following properties:
* Multiple messages sent in the same packet.
* Messages containing 1 or more 2-byte "chunks" that need removal before parsing
* Messages too long for a single packet -- TCP reassembly applied.
* Messages containing additional "nested" messages

### Without Dissector Installed
![alt text](https://git.vrt.sourcefire.com/dmcdaniel/Winbox_Toolkit/raw/master/Wireshark_Dissector/images/before-dissection.png "Without Dissector Installed")

### With Dissector Installed
![alt text](https://git.vrt.sourcefire.com/dmcdaniel/Winbox_Toolkit/raw/master/Wireshark_Dissector/images/dissected.png "With Dissector Installed")
