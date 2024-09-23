to run:

required installations (through terminal):
sudo apt-get update
cmake: sudo apt install cmake
openssl library: sudo apt-get install libssl-dev
boost: sudo apt-get install libboost-all-dev


delete "CMakeCache.txt"

cd into "src"

then do:
cmake ..

make

In one terminal do
> ./server

In another do (can be repeated to make many clients)
> ./client <username>

from a client you can do the following commands
1. > public_chat "message"  (sends a message to all connected clients)
2. > clients (shows all connected clients and their username/userids
