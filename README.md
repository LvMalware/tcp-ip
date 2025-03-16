# TCP/IP

## What is this?

This is a user-land implementation of the TCP/IP protocol using the Linux TAP interface. The goal was to have a deeper understanding about TCP/IP and other network protocols by implementing them myself. It also seemed like an interesting project to exercise Zig programming. I started by following [this](https://www.saminiir.com/lets-code-tcp-ip-stack-1-ethernet-arp/) guide and then filled the missing parts by reading the related RFCs.

## Implemented

Basics of:
- Ethernet
- IP functionality
- ARP request/response
- TCP functionality (connection, retransmission, etc.)

## Missing/TODO

- Handle Urgent data on the TCP

- Implement IP options and fragmentation

- Implement timeouts

- Many more
