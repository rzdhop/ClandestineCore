KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
obj-m := ClandestineCore.o

all:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean
