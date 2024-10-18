Group 69 SP Protocol Implementation

Members:

Easwar Allada - a1851456

Seojun Lee - a1849414

Khush Patel - a1852760

Yuqi Xiao - a1849716


Github Link: https://github.com/Jun10148/SP-Protocol

to run:

required installations (through terminal):
1. > sudo apt-get update (if required)
2. > cmake: sudo apt install cmake
3. > openssl library: sudo apt-get install libssl-dev
4. > boost: sudo apt-get install libboost-all-dev


Building the project:

1. delete src/"CMakeCache.txt" (if it exists)
2. cd into "src"
3. > cmake ..
4. > make



### Single Server Usage
1. cd into server1/
2. run ./server1_exec
3. Create a new terminal and run ./client1_exec [username] 
*note - using inputs such as () as a username will not work as it triggers a shell interpretation opening up bash instead  
4. Repeat step 3 to create more users as needed


#### From a client you can do the following commands
1. > clients (shows all connected clients and their username/userids)
2. > public_chat "message"  (sends a message to all connected clients)
3. > send_message [serverid]-[userid] "message" (sends message to specific user[s])


*note the [serverid]-[user-id] can be repeated to send messages to multiple users at once
e.g., send_message server1-1 server1-2 "hello 1 and 2"

IMPORTANT:
the "clients" command initialises the stored list of users that the current client can send to.
Hence, this command MUST be called prior to sending messages
However, running the "clients" command from 1 client will initialise the client list for all other active clients
This also means, if a new client is made, the user has to also run "clients" again from any client.

If this step is not done correctly, the program cannot correctly identify usernames and in place of username, the sender's public key will be used.

### Multi Server Usage
1. Open 2 terminals. One at server1/ and the other at server2/
2. Run ./server1_exec and ./server2_exec on each respective terminal
3. type in localhost:9003 on server1's terminal. Then type localhost:9002 on server2's

* Alternatively to the above, typing a different ip:port allows the server instance to connect to another running program if available

4. Much like the single server, create more terminals to create users using ./client1_exec [username] or ./client2_exec [username]
5. Interact between users similarly to the single server. Remember to initialise clients using "clients" for each server


