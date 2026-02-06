# Transfer File Service

## Overview
This project implements a **TCP-based file transfer service**, inspired by classic file transfer protocols. A multi-threaded server handles multiple clients, allowing directory listing and file downloads.

Communication is based on a **custom application-layer protocol** using serialized packets.

## Features
- Concurrent server handling multiple clients
- Custom protocol with opcodes and acknowledgements
- File transfers in fixed-size blocks (512 bytes)
- Directory listing support
- Robust error handling (protocol and file errors)

## Supported Commands
- `dir` – list available files on the server
- `get <remote> <local>` – download a file
- `end` – terminate client session

## Technologies
- Python
- TCP sockets
- Multithreading
- `pickle` for data serialization

## Skills Demonstrated
- Client–server architectures
- Protocol design
- Concurrent systems
- Network error handling

## Academic Context
Computer Networks (TPC1)
