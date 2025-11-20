#include <stdio.h>
#include <string.h>
#include <unistd.h>

#ifdef NO_VERITESTING
#define COMPARE_FUNC simple_cmp
#define FUNCNAME "simple_cmp"
#else
#define COMPARE_FUNC custom_cmp
#define FUNCNAME "custom_cmp"
#endif

const char correct_password[] = "ASDFQWERZXCV1234poiulkjh,mnb0987";

// just a wrapper
unsigned int simple_cmp(char *buf1, char *buf2, unsigned int length) {
    unsigned int result;
    result = memcmp(buf1, buf2, length);

    return result == 0 ? 32 : 0;
}


unsigned int custom_cmp(char *buf1, char *buf2, unsigned int length) {
    unsigned int count = 0;
    for (int i = 0; i < length; i++) {
        if (buf1[i] == buf2[i]) {
            count += 1;
        }
    }

    return count;
}


int main(int argc, char **argv) {
    char inp[0x20] = {0};
    unsigned int result;
    printf("compare function: %s\n", FUNCNAME);
    printf("input> ");
    
    read(STDIN_FILENO, inp, 0x20);

    result = COMPARE_FUNC(inp, (char *) correct_password, sizeof(inp));

    printf("compare result: %d\n", result);

    if (result == sizeof(inp)) {
        printf("OK\n");
        return 0;
    }

    printf("FAILED\n");
    return 1;
}