#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

#KERNELSRC := /usr/src/linux

ifeq ("$(KERNELSRC)","")
all:
	@echo 'set $$KERNELSRC!'
else
all: progs mods

mods:
	$(MAKE) modules -C $(KERNELSRC) SUBDIRS=$(shell pwd)/kernel

progs:
	$(MAKE) -C iscsid

install: kernel/iscsi_trgt_mod.o iscsid/iscsid
	@install -v iscsid/iscsid /usr/sbin/iscsi_trgtd
	@eval `sed -n '1,5s/^\([A-Z]*\) *= *\(.*\)$$/\1=\2/p' $(KERNELSRC)/Makefile`; \
	KERNELRELEASE=$$VERSION.$$PATCHLEVEL.$$SUBLEVEL$$EXTRAVERSION; \
	install -vD kernel/iscsi_trgt_mod.o $(INSTALL_MOD_PATH)/lib/modules/$$KERNELRELEASE/iscsi/iscsi_trgt_mod.o

clean:
	find -name "*.o" -o -name "*.a" -o -name ".*.flags" | xargs rm -f
	rm -f iscsid/iscsid

realclean: clean
	find -name "*~" -o -name "cscope.*" | xargs rm -rf

endif
