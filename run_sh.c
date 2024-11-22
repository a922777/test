#include <unistd.h>
int main() {
    char *args[] = {"/bin/sh", NULL};
    execv("/bin/sh", args);
    return 0;
}
