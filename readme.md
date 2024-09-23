to run:

required installations (through terminal):
1. > sudo apt-get update
2. > cmake: sudo apt install cmake
3. > openssl library: sudo apt-get install libssl-dev
4. > boost: sudo apt-get install libboost-all-dev


Building the project:

1. delete "CMakeCache.txt"
2. cd into "src"
3. > cmake ..
4. > make

In one terminal do
> ./server

In another do (can be repeated to make many clients)
> ./client <username>

from a client you can do the following commands
1. > public_chat "message"  (sends a message to all connected clients)
2. > clients (shows all connected clients and their username/userids
