# TCP/IP

## What is this?

This is a user-land implementation of the TCP/IP protocol using the Linux TAP interface. The goal was to have a deeper understanding about TCP/IP and other network protocols by implementing them myself. It also seemed like an interesting project to exercise Zig programming. I started by following [this](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/) guide and then filled the missing parts by reading the related RFCs.

## How to run it

You will need [Zig](https://ziglang.org/) (version 0.14.0) to build.

```
# Clone project
git clone https://github.com/LvMalware/tcp-ip

# cd into the folder
cd tcp-ip/

# build project
zig build

# Add `cap_net_admin` capability to the file:
sudo setcap cap_net_admin=ep zig-out/bin/stack

# Run the executable
./zig-out/bin/stack

```

By default, the tap interface will have the IP `10.0.0.4` and the program will run a TCP echo server listenning on port `5501`. Now you can use a tcp client like netcat to interact with it. 

```
nc 10.0.0.4 5501
```

## Implemented

Basics of:
- Ethernet
- IP functionality
- ICMP echo (ping) 
- ARP request/response
- TCP functionality (connection, retransmission, etc.)

## Missing/TODO

- Handle Urgent data on the TCP

- Implement IP options and fragmentation

- Implement timeouts

- Many more
