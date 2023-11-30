
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

const char* read_file_bytes(const char* path_to_file){
    FILE *file_pointer;
    char *buffer;
    long file_length;

    // Open the file in binary mode for reading
    file_pointer = fopen(path_to_file, "rb"); // Replace "path/to/your/file" with your file's path

    if (file_pointer == NULL) {
        perror("Error opening the file");
        return 0;
    }

    // Get the file length by seeking to the end and getting the position
    fseek(file_pointer, 0, SEEK_END);
    file_length = ftell(file_pointer);
    rewind(file_pointer);

    // Allocate memory for the buffer to store the file content
    buffer = (char *)malloc(file_length * sizeof(char));
    if (buffer == NULL) {
        fclose(file_pointer);
        perror("Memory allocation error");
        return 0;
    }

    // Read the file content into the buffer
    size_t read_result = fread(buffer, sizeof(char), file_length, file_pointer);

    if (read_result != file_length) {
        fclose(file_pointer);
        free(buffer);
        perror("Error reading file");
        return 0;
    }

    fclose(file_pointer);
    free(buffer);

    return buffer;
}

void print_file_bytes(const char* file_path) {
    FILE *file_pointer = fopen(file_path, "rb");
    if (file_pointer == NULL) {
        perror("Error opening the file");
        return;
    }

    // Seek to the end of the file to determine its size
    fseek(file_pointer, 0, SEEK_END);
    long file_size = ftell(file_pointer);
    rewind(file_pointer);

    // Allocate memory for the buffer to store the file content
    unsigned char *buffer = (unsigned char *)malloc(file_size * sizeof(unsigned char));
    if (buffer == NULL) {
        fclose(file_pointer);
        perror("Memory allocation error");
        return;
    }

    // Read the file content into the buffer
    size_t read_result = fread(buffer, sizeof(unsigned char), file_size, file_pointer);

    if (read_result != file_size) {
        fclose(file_pointer);
        free(buffer);
        perror("Error reading file");
        return;
    }

    fclose(file_pointer);

    // Print bytes in hexadecimal format
    for (long i = 0; i < file_size; ++i) {
        printf("%02X ", buffer[i]); // Print byte in hexadecimal format
        if ((i + 1) % 16 == 0) {     // Print new line after every 16 bytes
            printf("\n");
        }
    }

    free(buffer);
}