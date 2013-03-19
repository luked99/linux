ifeq ($(CONFIG_MACH_BCM2708),y)

obj-$(CONFIG_BCM2708_VCHIQ)	+= vchiq.o

vchiq-objs := \
   interface/vchiq_arm/vchiq_core.o  \
   interface/vchiq_arm/vchiq_arm.o \
   interface/vchiq_arm/vchiq_kern_lib.o \
   interface/vchiq_arm/vchiq_2835_arm.o \
   interface/vchiq_arm/vchiq_proc.o \
   interface/vchiq_arm/vchiq_shim.o \
   interface/vchiq_arm/vchiq_util.o \
   interface/vchiq_arm/vchiq_connected.o \

EXTRA_CFLAGS += -DVCOS_VERIFY_BKPTS=1 -Idrivers/misc/vc04_services -DUSE_VCHIQ_ARM -D__VCCOREVER__=0x04000000
ccflags-$(CONFIG_BCM2708_VCHIQ)  += -I"drivers/misc/vc04_services/interface/debug_sym"

vchiq-objs += interface/debug_sym/debug_sym.o

endif

