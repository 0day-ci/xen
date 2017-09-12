include $(XEN_ROOT)/Config.mk

NOTE_SYMBOL = "note_depends"
NOTE_DEPENDS = "const  __section(\".livepatch.depends\") $(NOTE_SYMBOL)"
CODE_ADDR=$(shell nm --defined $(1) | grep $(2) | awk '{print "0x"$$1}')
CODE_SZ=$(shell nm --defined -S $(1) | grep $(2) | awk '{ print "0x"$$2}')

.PHONY: default

LIVEPATCH := xen_hello_world.livepatch
LIVEPATCH_BYE := xen_bye_world.livepatch
LIVEPATCH_REPLACE := xen_replace_world.livepatch
LIVEPATCH_NOP := xen_nop.livepatch

LIVEPATCHES += $(LIVEPATCH)
LIVEPATCHES += $(LIVEPATCH_BYE)
LIVEPATCHES += $(LIVEPATCH_REPLACE)
LIVEPATCHES += $(LIVEPATCH_NOP)

LIVEPATCH_DEBUG_DIR ?= $(DEBUG_DIR)/xen-livepatch

build default: livepatch

install: livepatch
	$(INSTALL_DIR) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)
	$(INSTALL_DATA) $(LIVEPATCHES) $(DESTDIR)$(LIVEPATCH_DEBUG_DIR)

uninstall:
	cd $(DESTDIR)$(LIVEPATCH_DEBUG_DIR) && rm -f $(LIVEPATCHES)

.PHONY: clean
clean::
	rm -f *.o .*.o.d *.livepatch config.h livepatch_depends.h hello_world_livepatch_depends.h *.bin

#
# To compute these values we need the binary files: xen-syms
# and xen_hello_world_func.o to be already compiled.
#
.PHONY: config.h
config.h: OLD_CODE_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_extra_version)
config.h: NEW_CODE_SZ=$(call CODE_SZ,$<,xen_hello_world)
config.h: MINOR_VERSION_SZ=$(call CODE_SZ,$(BASEDIR)/xen-syms,xen_minor_version)
config.h: MINOR_VERSION_ADDR=$(call CODE_ADDR,$(BASEDIR)/xen-syms,xen_minor_version)
config.h: xen_hello_world_func.o
	(set -e; \
	 echo "#define NEW_CODE_SZ $(NEW_CODE_SZ)"; \
	 echo "#define MINOR_VERSION_SZ $(MINOR_VERSION_SZ)"; \
	 echo "#define MINOR_VERSION_ADDR $(MINOR_VERSION_ADDR)"; \
	 echo "#define OLD_CODE_SZ $(OLD_CODE_SZ)") > $@

xen_hello_world.o: config.h livepatch_depends.h

.PHONY: $(LIVEPATCH)
$(LIVEPATCH): xen_hello_world_func.o xen_hello_world.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH) $^
	$(OBJCOPY) --strip-debug --strip-symbol=$(NOTE_SYMBOL) $@

#
# This target is only accessible if CONFIG_LIVEPATCH is defined, which
# depends on $(build_id_linker) being available. Hence we do not
# need any checks.
#
# N.B. The reason we don't use arch/x86/note.o is that it may
# not be built (it is for EFI builds), and that we do not have
# the note.o.bin to muck with (as it gets deleted)
#
.PHONY: note.bin
note.bin:
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(BASEDIR)/xen-syms $@

.PHONY: livepatch_depends.h
livepatch_depends.h: note.bin
	$(shell (../../../tools/firmware/hvmloader/mkhex $(NOTE_DEPENDS) $^ > $@))

#
# Extract the build-id of the xen_hello_world.livepatch
# (which xen_bye_world will depend on).
#
.PHONY: hello_world_note.bin
hello_world_note.bin: $(LIVEPATCH)
	$(OBJCOPY) -O binary --only-section=.note.gnu.build-id $(LIVEPATCH) $@

.PHONY: hello_world_livepatch_depends.h
hello_world_livepatch_depends.h: hello_world_note.bin
	$(shell (../../../tools/firmware/hvmloader/mkhex $(NOTE_DEPENDS) $^ > $@))

xen_bye_world.o: config.h hello_world_livepatch_depends.h

.PHONY: $(LIVEPATCH_BYE)
$(LIVEPATCH_BYE): xen_bye_world_func.o xen_bye_world.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_BYE) $^
	$(OBJCOPY) --strip-debug --strip-symbol=$(NOTE_SYMBOL) $@

xen_replace_world.o: config.h livepatch_depends.h

.PHONY: $(LIVEPATCH_REPLACE)
$(LIVEPATCH_REPLACE): xen_replace_world_func.o xen_replace_world.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_REPLACE) $^
	$(OBJCOPY) --strip-debug --strip-symbol=$(NOTE_SYMBOL) $@

xen_nop.o: config.h livepatch_depends.h

.PHONY: $(LIVEPATCH_NOP)
$(LIVEPATCH_NOP): xen_nop.o
	$(LD) $(LDFLAGS) $(build_id_linker) -r -o $(LIVEPATCH_NOP) $^
	$(OBJCOPY) --strip-debug --strip-symbol=$(NOTE_SYMBOL) $@

.PHONY: livepatch
livepatch: $(LIVEPATCH) $(LIVEPATCH_BYE) $(LIVEPATCH_REPLACE) $(LIVEPATCH_NOP)
