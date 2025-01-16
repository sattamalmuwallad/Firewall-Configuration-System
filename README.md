# Firewall Configuration System

## Overview
This project is a server-client application for managing a firewall's configuration. The system allows users to interact with a server program to add, query, and manage firewall rules, as well as check connections against these rules. The project emphasizes concurrency and memory safety while providing a robust interface for rule management.

## Features
- **Server-Side Operations**:
  - Add firewall rules (`A <rule>`).
  - List all requests in the order they were received (`R`).
  - Check if an IP address and port are allowed based on the rules (`C <IPAddress> <port>`).
  - Delete a firewall rule (`D <rule>`).
  - List all firewall rules along with associated queries (`L`).
  - Handle invalid commands gracefully with appropriate error messages.
  
- **Client-Side Interaction**:
  - Send commands to the server via standard input or network sockets.
  - Display server responses in the client application.

## Technologies Used
- **Programming Language**: C
- **Concurrency**: Multi-threaded server for handling multiple client connections.
- **Networking**: TCP/IP for server-client communication.

## Setup
### Prerequisites
- A Linux environment or the provided virtual machine.
- GCC for compiling the source code.

### Compilation
1. Place `server.c` and `client.c` in the same directory as the `Makefile`.
2. Run the following command to compile the project:
   ```bash
   make
