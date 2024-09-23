#include <iostream>
#include <thread>
#include <atomic>
#include <unistd.h>
#include <termios.h>

std::atomic<bool> running(true);

// Function to print a message every 5 seconds
void printMessage() {
    while (running) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        std::cout << "This message prints every 5 seconds.\n";
    }
}

// Function to hide input
void hideInput() {
    std::string input;

    // Save current terminal settings
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO); // Disable canonical mode and echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (running) {
        input.clear(); // Clear the previous input

        // Read input without displaying it
        char ch;
        while ((ch = getchar()) != '\n') { // Stop on Enter key
            input += ch;
        }

        // Check for exit command
        if (input == "exit") {
            running = false;
        } else {
            std::cout << "Input received: " << input << std::endl;
        }
    }

    // Restore old terminal settings
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
}

int main() {
    std::thread messageThread(printMessage);
    std::thread inputThread(hideInput);

    inputThread.join(); // Wait for input thread to finish
    running = false; // Signal the message thread to stop
    messageThread.join(); // Wait for message thread to finish

    return 0;
}