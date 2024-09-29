// myfile.hpp

#ifndef NORMAL_FUNCTION_HPP  // Include guard
#define NORMAL_FUNCTION_HPP

#include <string>
#include <fstream>
#include <iostream>

// Function to create a text file
void normal_function() {
    std::ofstream outFile("suspicious.txt");  // Open the file
    if (outFile.is_open()) {
        outFile << "Malicious script";           // Write content to the file
        outFile.close();              // Close the file
    }
}

void normal_function2() {
    std::cout << "Backdoor activated" << std::endl;
}

#endif // MYFILE_HPP