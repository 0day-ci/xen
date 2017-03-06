include $(ROOT)/build/common.mk

NAME      := pagetable-emulation
CATEGORY  := functional
TEST-ENVS := hvm32pse hvm32pae hvm64

VARY-CFG  := hap shadow

obj-perenv += stubs.o main.o

include $(ROOT)/build/gen.mk
