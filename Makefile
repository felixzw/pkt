acc-objs:=acc_core.o acc_conn.o acc_sk.o 
obj-m:=acc.o
        KERNELPATH="/usr/src/kernels/2.6.32-431.5.1.el6.x86_64"
all:
	make -C $(KERNELPATH) M=$(shell pwd)  
clean:
	rm -f *.o *.ko *.unsigned *.order *.symvers *.mod.c 
	rm -f  .*.cmd 
	rm -rf .tmp_versions
