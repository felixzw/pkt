obj-m += acc.o
acc-objs:=acc_conn.o acc_sk.o
        KERNELPATH="/usr/src/kernels/2.6.32-358.el6.i686/"
all:
	make -C $(KERNELPATH) M=$(shell pwd)  
clean:
	rm -f *.o *.ko *.unsigned *.order *.symvers *.mod.c *.cmd
