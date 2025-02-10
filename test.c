#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME_LENGTH 10

void unsafe_copy_function(char *dest) {
    char source[50] = "This is a very long string that will cause buffer overflow";
    
    // Buffer overflow risk
    strcpy(dest, source);
}

void unsafe_input_function() {
    char buffer[MAX_NAME_LENGTH];
    
    // Unsafe input
    printf("Enter your name: ");
    gets(buffer);  // VERY UNSAFE: No bounds checking
}

void pointer_dereferencing_risk() {
    int *ptr = NULL;
    
    // Dangerous null pointer dereference
    *ptr = 42;  // This will cause a segmentation fault
}

void memory_allocation_risk() {
    // Unsafe memory allocation without validation
    char *buffer = malloc(1000);  // No check for allocation success
    if (buffer == NULL) {
        // Proper error handling missing
        return;
    }
    
    // No bounds checking in string operations
    strcpy(buffer, "Potential buffer overflow content");
    
    free(buffer);
    
    // Dangerous
    buffer[0] = 'X';  // Accessing freed memory
}

int main() {
    char dest[5];  // Small buffer
    
    // Multiple security risks demonstrated
    unsafe_copy_function(dest);
    unsafe_input_function();
    pointer_dereferencing_risk();
    memory_allocation_risk();
    
    return 0;
}