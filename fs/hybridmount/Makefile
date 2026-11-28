obj-$(CONFIG_HYBRIDMOUNT) += hybridmount.o
ccflags-y += -std=gnu11 -Wno-declaration-after-statement
ccflags-y += $(shell grep -qs "static inline void vm_flags_clear" "$(srctree)/include/linux/mm.h" && echo -DHM_HAVE_VM_FLAGS_CLEAR)
ccflags-y += $(shell grep -qsw __s_d_op "$(srctree)/include/linux/fs.h" && echo -DHM_HAVE_SB_PRIVATE_D_OP)
ccflags-y += $(shell test -r "$(srctree)/include/linux/xattr.h" && tr "\n" " " < "$(srctree)/include/linux/xattr.h" | grep -qE "\([[:space:]]*\*[[:space:]]*__get[[:space:]]*\)" && echo -DHM_HAVE_XATTR__GET)
