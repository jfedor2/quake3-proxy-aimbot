# Quake 3 Proxy Aimbot

This is a proxy for Quake III Arena with a proof-of-concept aimbot functionality. It also works with Quake Live.

Its main purpose is to serve as a companion piece to [this article](https://www.jfedor.org/quake3/) and help understand the game’s network protocol. It may also be useful for observing the game’s behavior under various network conditions as it can simulate latency and packet loss.

The program can work in three modes: it can be a SOCKS proxy, a one-server proxy, or just read packets from a tcpdump/Wireshark capture file.

It's written in Python 3.

## SOCKS proxy mode

It is a little known fact that Quake 3 (only the Windows version) can be configured to work with a UDP SOCKS proxy. To start the proxy in SOCKS mode, run it with the following command line arguments:

`--listen-port 30000 --socks-port 30000 --socks-public-address 127.0.0.1`

To make Quake 3 use the proxy, set the following console variables and restart the game:

`net_socksServer 127.0.0.1`

`net_socksPort 30000`

`net_socksEnabled 1`

If the proxy is not running on the same machine as the game, change 127.0.0.1 to the address of the machine that the proxy is running on. When you don't want to use the proxy anymore, set `net_socksEnabled` to 0 and restart.

In this mode, the proxy supports multiple clients and servers at the same time.

## One-server proxy mode

In this mode the proxy only connects to one predefined server, but still supports multiple clients. To start the proxy in one-server mode, run it with the following command line arguments:

`--server-address <server_address> --server-port <server_port> --listen-port 30000`

Then in Quake 3, instead of using the game’s browser to connect to a server, use the console to connect to the proxy:

`connect 127.0.0.1:30000`

Again, change 127.0.0.1 to the correct address if the proxy is not running on the same machine as the game.

## Read captured packets mode

In this mode, the program doesn’t make any network connections but instead reads packets from a capture file that was created earlier with a tool like tcpdump or Wireshark. It may be useful when analyzing the protocol. For this mode to work, [Scapy](https://scapy.net/) is required.

To start the program in this mode, run it with the following command line arguments:

`--read-dump <filename> --server-address <server_address> --server-port <server_port>`

Server address is required so that the program knows which packets to process and which side is the server. It will only work correctly when there was only one client.

By default the program doesn’t output much information about the processed traffic, so it might be a good idea to also use the `--print-packets-as-html` parameter or add some prints in the appropriate places.

## Aimbot

The proxy can optionally rewrite some of the client packets and modify the direction in which the player is looking to make them aim at an enemy. It will do this when the player is pressing the fire button and the currently selected weapon is the machinegun, the shotgun, the lightning gun or the railgun. It will choose the enemy that’s closest to the crosshairs (it will happily shoot at teammates). Optionally it will restrict the aiming to enemies within a configured angular diameter around the crosshairs.

To start the proxy with aimbot enabled, run it with the following command line arguments (in addition to the ones for SOCKS proxy or one-server proxy):

`--aimbot --aimbot-fov 60`

Change the 60 degrees value to taste. If the `--aimbot-fov` parameter is not supplied, the proxy will aim at all enemies, even those behind the player.

Here’s a video demonstrating the aimbot functionality in Quake 3:

https://youtu.be/L8HfcJIo3rk

And in Quake Live (note that the weapon effects are simulated locally in this case so it’s not obvious that the aiming direction was modified):

https://youtu.be/Z9wHycH_zdY

## Quake Live protocol

Surprisingly, Quake Live’s protocol (at least as of this writing) is almost unchanged from Quake 3. Neither the fixed Huffman tree, nor the XOR scrambling keys were modified. The only apparent changes are an additional byte before the user commands in client packets and slightly modified field definitions for playerstate and entities (see defs.py).

## Command line parameters

Here's a full list of command line parameters.

`-h`, `--help`: show help message and exit

`--server-address <address>`: server address to connect to

`--server-port <port>`: server port to connect to, 27960 by default

`--listen-port <port>`: port to listen on

`--socks-port <port>`: SOCKS proxy port to listen on

`--socks-public-address <address>`: public address to give to SOCKS proxy clients

`--client-to-server-delay <milliseconds>`: simulated network latency for client-to-server packets

`--server-to-client-delay <milliseconds>`: simulated network latency for server-to-client packets

`--client-to-server-packet-loss <percent>`: simulated packet loss for client-to-server packets

`--server-to-client-packet-loss <percent>`: simulated packet loss for server-to-client packets

`--aimbot`: enable aimbot

`--aimbot-fov <degrees>`: only auto-aim at targets within a cone this wide around the crosshair

`--read-dump <filename>`: read and process a tcpdump/wireshark \*.pcap file instead of doing live traffic

`--print-packets-as-html`: print the processed contents of all packets as HTML

`--dont-print-exceptions`: suppress printing exceptions that occur during traffic processing

`--debug-level <debug_level>`: verbosity, 2 prints something for every packet, default: 1
