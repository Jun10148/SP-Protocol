to run:

required installations (through terminal):
1. > sudo apt-get update (if required)
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

Create another terminal and do (can be repeated to make many clients)
> ./client [username]


from a client you can do the following commands
1. > clients (shows all connected clients and their username/userids)
2. > public_chat "message"  (sends a message to all connected clients)
3. > send_message [serverid]-[userid] "message" (sends message to specific user[s])

*note the [serverid]-[user-id] can be repeated to send messages to multiple users at once
e.g., send_message server1-1 server1-2 "hello 1 and 2"

IMPORTANT:
the "clients" command initialises the stored list of users that the current client can send to.
Hence, this command MUST be called prior to sending messages
However, running the "clients" command from 1 client will initialise the client list for all other active clients
This also means, if a new client is made, the user has to also run "clients" from any client