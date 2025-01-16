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
   ```

### Running the Server
1. To run the server interactively:
   ```bash
   ./server -i
   ```
2. To run the server with networking:
   ```bash
   ./server <port>
   ```

### Running the Client
1. Use the following syntax to run the client:
   ```bash
   ./client <serverHost> <serverPort> <command>
   ```

## Usage Examples
- Adding a firewall rule:
  ```bash
  ./client localhost 2200 A 147.188.192.0-147.188.193.255 22-80
  ```
- Checking a connection:
  ```bash
  ./client localhost 2200 C 147.188.192.1 22
  ```
- Deleting a firewall rule:
  ```bash
  ./client localhost 2200 D 147.188.192.0-147.188.193.255 22-80
  ```

## Project Structure
- `server.c`: The main server program handling requests.
- `client.c`: The client program for sending commands to the server.
- `Makefile`: Build automation for compiling the project.
- `test.sh`: A basic script for testing the server's functionality.

## Future Work
- Implement additional commands for advanced firewall management.
- Enhance concurrency handling and stress-test performance under heavy load.
- Expand the test suite for more robust functionality checks.

## Acknowledgments
This project is part of the Operating Systems and Systems Programming course at the University of Birmingham. Special thanks to Professors Eike Ritter and David Oswald for their guidance and provided resources.
