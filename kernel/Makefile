#
# Makefile for the Linux kernel device drivers.
#
# Note! Dependencies are done automagically by 'make dep', which also
# removes any old dependencies. DON'T put your own dependencies here
# unless it's something special (not a .c file).
#
# Note 2! The CFLAGS definitions are now in the main makefile.

ISCSI_OBJS := target.o target_bdev.o iscsi.o iscsi_proc.o
EXTRA_CFLAGS := -g -fno-inline

obj-m := iscsi_trgt_mod.o $(ISCSI_OBJS)

iscsi_trgt_mod.o: $(ISCSI_OBJS)
	$(LD) -r -o iscsi_trgt_mod.o $(ISCSI_OBJS)

-include $(TOPDIR)/Rules.make
