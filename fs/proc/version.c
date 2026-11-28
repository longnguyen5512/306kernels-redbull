// SPDX-License-Identifier: GPL-2.0
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/rwsem.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/utsname.h>

#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
extern struct static_key_false susfs_is_uname_spoof_buffer_set;
extern void susfs_spoof_uname(struct new_utsname *tmp);
#endif

static int version_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
	if (current_uid().val >= 10000 &&
	    static_branch_unlikely(&susfs_is_uname_spoof_buffer_set)) {
		struct new_utsname tmp;

		down_read(&uts_sem);
		memcpy(&tmp, utsname(), sizeof(tmp));
		susfs_spoof_uname(&tmp);
		up_read(&uts_sem);
		seq_printf(m,
			"%s version %s (android-build@abfarm-us-west1-c-0001) "
			"(Android (10087095, +pgo, +bolt, +lto, -mlgo, based on r487747c) "
			"clang version 17.0.2, LLD 17.0.2) %s\n",
			tmp.sysname,
			tmp.release,
			tmp.version);
		return 0;
	}
#endif
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int __init proc_version_init(void)
{
	proc_create_single("version", 0, NULL, version_proc_show);
	return 0;
}
fs_initcall(proc_version_init);
