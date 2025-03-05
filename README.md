# ClandestineCore
Un super Rootkit kernel ! 

---

TODOs : 
- (kprobe)    Hook kill signales -> if SIGxxx then xxx()
- (kretprobe) Hook retKill -> return success
  - SIGALWRECV (50) -> Register misc_device() -> register data
      - IOCTL (0x100) -> Register remote ip
      - IOCTL (0x200) -> Register remote port
      - IOCTL (0x300) -> Register Data sent
  - SIGREMRECV (51) -> Unregister misc_device -> close device
  - SIGHIDEMOD (52) -> hide module from lsmod
  - SIGSENDNET (53) -> send registered data over tcp socket
