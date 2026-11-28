#include <linux/fs.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/namei.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/version.h>
#include <linux/vmalloc.h>
#include <linux/mm.h>
#include <linux/ptrace.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/proc_fs.h>
#include <linux/kthread.h>
#include <linux/delay.h>

#include "policy/feature.h"
#include "ksu.h"
#include "uapi/feature.h"
#include "selinux/selinux.h"
#include "feature/selinux_hide.h"
#include "compat/kernel_compat.h"

#ifndef __nocfi
#define __nocfi
#endif

#ifdef KSU_COMPAT_USE_SELINUX_STATE
extern struct selinux_state selinux_state;
extern int security_context_to_sid(struct selinux_state *state,
				   const char *scontext, u32 scontext_len,
				   u32 *out_sid, gfp_t gfp);
#define KSU_HAS_SELINUX_STATE 1
#else
#define KSU_HAS_SELINUX_STATE 0
#endif

#ifndef SIMPLE_TRANSACTION_LIMIT
#define SIMPLE_TRANSACTION_LIMIT (PAGE_SIZE - 1)
#endif

#define KSU_SEL_CONTEXT_INO 5
#define KSU_SEL_ACCESS_INO  6

static bool ksu_selinux_hide_enabled __read_mostly = true;

struct ksu_hide_buf {
    size_t len;
    char   data[];
} __aligned(sizeof(size_t));

static struct ksu_hide_buf __rcu *ksu_hide_type_list = NULL;
static struct ksu_hide_buf __rcu *ksu_hide_rule_list = NULL;
static u64 ksu_hide_type_bloom __read_mostly = 0;
static DEFINE_MUTEX(ksu_hide_list_mutex);

#define KSU_FAST_TYPE_SLOTS 256
struct ksu_fast_type_slot {
    u64 hash;
    u64 hash2;
    u8  len;
    char name[31];
};
static struct ksu_fast_type_slot ksu_fast_types[KSU_FAST_TYPE_SLOTS];

static inline u64 ksu_type_fnv64(const char *s, size_t len)
{
    u64 h = 14695981039346656037ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= (u8)s[i];
        h *= 1099511628211ULL;
    }
    return h;
}

static inline u64 ksu_type_fnv64_alt(const char *s, size_t len)
{
    u64 h = 0x9e3779b97f4a7c15ULL;
    size_t i;

    for (i = 0; i < len; i++) {
        h ^= (u8)s[i];
        h *= 0xbf58476d1ce4e5b9ULL;
    }
    return h;
}

static inline u64 ksu_type_bloom_mask(u64 h)
{
    return (1ULL << (h & 63)) | (1ULL << ((h >> 6) & 63));
}

static void ksu_fast_type_insert(const char *name, size_t len)
{
    u64 h = ksu_type_fnv64(name, len);
    u64 h2 = ksu_type_fnv64_alt(name, len);
    size_t idx = (size_t)(h & (KSU_FAST_TYPE_SLOTS - 1));
    size_t step;

    if (!len || len >= sizeof(ksu_fast_types[0].name))
        return;

    for (step = 0; step < KSU_FAST_TYPE_SLOTS; step++) {
        struct ksu_fast_type_slot *s = &ksu_fast_types[(idx + step) & (KSU_FAST_TYPE_SLOTS - 1)];
        if (s->len == 0) {
            s->hash = h;
            s->hash2 = h2;
            memcpy(s->name, name, len);
            s->name[len] = '\0';
            smp_store_release(&s->len, (u8)len);
            return;
        }
        if (s->len == len && s->hash == h && !memcmp(s->name, name, len))
            return;
    }
}

static void ksu_rcu_replace(struct ksu_hide_buf __rcu **slot, struct ksu_hide_buf *new_buf)
{
    struct ksu_hide_buf *old = rcu_dereference_protected(*slot, 1);
    rcu_assign_pointer(*slot, new_buf);
    synchronize_rcu();
    kfree(old);
}

void ksu_selinux_hide_add_type(const char *name)
{
    struct ksu_hide_buf *old_buf, *new_buf;
    size_t old_len, need, i, name_len;

    if (!name || !*name)
        return;

    name_len = strlen(name);
    need = name_len + 3;

    mutex_lock(&ksu_hide_list_mutex);
    old_buf = rcu_dereference_protected(ksu_hide_type_list, 1);
    old_len = old_buf ? old_buf->len : 0;

    if (old_buf) {
        for (i = 0; i < old_len; ) {
            const char *cur = old_buf->data + i;
            if (!strncmp(cur + 1, name, name_len) && cur[name_len + 1] == ':')
                goto out;
            i += strlen(cur) + 1;
        }
    }

    new_buf = kmalloc(sizeof(*new_buf) + old_len + need, GFP_KERNEL);
    if (!new_buf)
        goto out;
    new_buf->len = old_len + need;
    if (old_buf && old_len)
        memcpy(new_buf->data, old_buf->data, old_len);
    sprintf(new_buf->data + old_len, ":%s:", name);

    ksu_rcu_replace(&ksu_hide_type_list, new_buf);
    ksu_fast_type_insert(name, name_len);
    WRITE_ONCE(ksu_hide_type_bloom,
               ksu_hide_type_bloom | ksu_type_bloom_mask(ksu_type_fnv64(name, name_len)));
    pr_info_ratelimited("selinux_hide: track type: :%s:\n", name);

out:
    mutex_unlock(&ksu_hide_list_mutex);
}

void ksu_selinux_hide_add_rule(const char *src, const char *tgt)
{
    struct ksu_hide_buf *old_buf, *new_buf;
    size_t old_len, need_src, need_tgt, need, i;
    char *p;

    if (!src || !*src || !tgt || !*tgt)
        return;

    need_src = strlen(src) + 3;
    need_tgt = strlen(tgt) + 3;
    need     = need_src + need_tgt;

    mutex_lock(&ksu_hide_list_mutex);
    old_buf = rcu_dereference_protected(ksu_hide_rule_list, 1);
    old_len = old_buf ? old_buf->len : 0;

    if (old_buf) {
        for (i = 0; i < old_len; ) {
            const char *csrc = old_buf->data + i;
            size_t ssz = strlen(csrc) + 1;
            const char *ctgt = csrc + ssz;
            size_t tsz = strlen(ctgt) + 1;

            if (!strcmp(csrc + 1, src) && !strcmp(ctgt + 1, tgt))
                goto out;
            i += ssz + tsz;
        }
    }

    new_buf = kmalloc(sizeof(*new_buf) + old_len + need, GFP_KERNEL);
    if (!new_buf)
        goto out;
    new_buf->len = old_len + need;
    if (old_buf && old_len)
        memcpy(new_buf->data, old_buf->data, old_len);

    p = new_buf->data + old_len;
    sprintf(p, ":%s:", src);
    p += strlen(p) + 1;
    sprintf(p, ":%s:", tgt);

    ksu_rcu_replace(&ksu_hide_rule_list, new_buf);
    pr_info_ratelimited("selinux_hide: track rule: :%s: -> :%s:\n", src, tgt);

out:
    mutex_unlock(&ksu_hide_list_mutex);
}

static bool ksu_should_hide_context(const char *str)
{
    struct ksu_hide_buf *buf;
    size_t off;

    if (!str)
        return false;

    rcu_read_lock();

    buf = rcu_dereference(ksu_hide_type_list);
    if (buf) {
        size_t len = buf->len;
        off = 0;
        while (off < len) {
            const char *entry = buf->data + off;
            if (strstr(str, entry)) {
                rcu_read_unlock();
                return true;
            }
            off += strlen(entry) + 1;
        }
    }

    buf = rcu_dereference(ksu_hide_rule_list);
    if (buf) {
        size_t len = buf->len;
        off = 0;
        while (off < len) {
            const char *src = buf->data + off;
            size_t ssz = strlen(src) + 1;
            const char *tgt = src + ssz;
            size_t tsz = strlen(tgt) + 1;

            if (strstr(str, src) && strstr(str, tgt)) {
                rcu_read_unlock();
                return true;
            }
            off += ssz + tsz;
        }
    }

    rcu_read_unlock();
    return false;
}

bool ksu_selinux_hide_is_hidden_ctx(const char *str)
{
    if (unlikely(!ksu_selinux_hide_enabled))
        return false;
    if (current_uid().val < 10000)
        return false;
    return ksu_should_hide_context(str);
}

const char *ksu_selinux_hide_rewrite_fast(const char *str, size_t size,
                                          char *buf, size_t buf_sz)
{
    size_t i, type_off = 0, type_len = 0, idx;
    int colons = 0;
    bool hit = false;
    u64 h, h2;

    if (unlikely(!ksu_selinux_hide_enabled) || current_uid().val < 10000 ||
        !str || !size || size >= buf_sz)
        return str;

    for (i = 0; i < size; i++) {
        if (str[i] == ':') {
            colons++;
            if (colons == 2) {
                type_off = i + 1;
            } else if (colons == 3) {
                type_len = i - type_off;
                break;
            }
        }
    }
    if (!type_off)
        return str;
    if (!type_len)
        type_len = size - type_off;
    if (!type_len || type_len >= sizeof(ksu_fast_types[0].name))
        return str;

    h = ksu_type_fnv64(str + type_off, type_len);
    h2 = ksu_type_fnv64_alt(str + type_off, type_len);
    idx = (size_t)(h & (KSU_FAST_TYPE_SLOTS - 1));
    {
        const struct ksu_fast_type_slot *s0 = &ksu_fast_types[idx];
        const struct ksu_fast_type_slot *s1 =
            &ksu_fast_types[(idx + 1) & (KSU_FAST_TYPE_SLOTS - 1)];
        u64 d0 = (u64)(READ_ONCE(s0->len) ^ (u8)type_len) |
                 (READ_ONCE(s0->hash) ^ h) | (READ_ONCE(s0->hash2) ^ h2);
        u64 d1 = (u64)(READ_ONCE(s1->len) ^ (u8)type_len) |
                 (READ_ONCE(s1->hash) ^ h) | (READ_ONCE(s1->hash2) ^ h2);

        hit = ((unsigned int)(d0 == 0) | (unsigned int)(d1 == 0)) != 0;
    }

    memcpy(buf, str, size);
    buf[size] = '\0';
    {
        static const char tag[3] = { 'u', '4', 'i' };
        size_t j;

        /* Write branchlessly in-place so hit/miss paths touch the same cache line. */
        for (j = 0; j < 3 && j < type_len; j++) {
            char orig = buf[type_off + j];
            WRITE_ONCE(buf[type_off + j], hit ? tag[j] : orig);
        }
    }
    return buf;
}

struct ksu_dirty_rule {
    const char *scon;
    const char *tcon;
};

static const struct ksu_dirty_rule ksu_dirty_rules[] = {
    { "u:r:shell:s0",         "u:r:su:s0"                   },
    { "u:r:adbd:s0",          "u:r:adbroot:s0"              },
    { "u:r:zygote:s0",        "u:object_r:adb_data_file:s0" },
    { "u:r:magisk:s0",        "u:r:droidspacesd:s0"         },
    { "u:r:su:s0",            "u:r:droidspacesd:s0"         },
    { "u:r:system_server:s0", "u:r:droidspacesd:s0"         },
    { "u:r:kernel:s0",        "u:object_r:adb_data_file:s0" },
    { "u:r:dex2oat:s0",       "u:object_r:dex2oat_exec:s0"  },
};

static bool ksu_is_dirty_access_query(const char *scon, const char *tcon)
{
    int i;

    for (i = 0; i < ARRAY_SIZE(ksu_dirty_rules); i++) {
        const struct ksu_dirty_rule *r = &ksu_dirty_rules[i];
        if (!strcmp(scon, r->scon) && !strcmp(tcon, r->tcon))
            return true;
    }
    return false;
}

static void ksu_fix_access_response(void *private_data, bool deny, u32 deny_mask)
{
    struct simple_transaction_argresp *ar = private_data;
    unsigned int allowed, ff, auditallow, auditdeny, flags, seqno;
    char buf[64];
    int len;

    if (!ar)
        return;

    if (sscanf(ar->data, "%x %x %x %x %u %x",
               &allowed, &ff, &auditallow, &auditdeny, &seqno, &flags) != 6)
        return;

    if (deny) {
        allowed    = 0;
        auditallow = 0;
        auditdeny  = 0xffffffff;
        flags      = 0;
    } else if (deny_mask) {
        allowed    &= ~deny_mask;
        auditallow &= ~deny_mask;
        auditdeny  |= deny_mask;
    }

    seqno = 1;

    len = scnprintf(buf, sizeof(buf), "%x %x %x %x %u %x",
                    allowed, 0xffffffff, auditallow, auditdeny, seqno, flags);

    if (len > 0 && len < (int)SIMPLE_TRANSACTION_LIMIT) {
        memcpy(ar->data, buf, len);
        ar->data[len] = '\0';
        ar->size = len;
    }
}

static int ksu_patch_fops_slot(void **slot, void *new_fn)
{
    unsigned long addr   = (unsigned long)slot;
    unsigned long base   = addr & PAGE_MASK;
    unsigned long offset = addr & ~PAGE_MASK;
    struct page *page    = phys_to_page(__pa(base));
    void *w;

    if (!page)
        return -EFAULT;

    w = vmap(&page, 1, VM_MAP, PAGE_KERNEL);
    if (!w)
        return -ENOMEM;

    WRITE_ONCE(*(void **)((unsigned long)w + offset), new_fn);
    smp_mb();
    vunmap(w);
    return 0;
}

static struct file_operations *ksu_resolve_fops(const char *path_str)
{
    struct path path;
    struct file_operations *fops = NULL;

    if (kern_path(path_str, LOOKUP_FOLLOW, &path))
        return NULL;
    if (path.dentry && d_inode(path.dentry))
        fops = (struct file_operations *)d_inode(path.dentry)->i_fop;
    path_put(&path);
    return fops;
}

static ssize_t (*orig_sel_write)(struct file *, const char __user *, size_t, loff_t *);
static struct file_operations *g_sel_context_fops;

static __nocfi ssize_t ksu_sel_write(struct file *file, const char __user *ubuf, size_t size, loff_t *pos)
{
    ino_t ino;
    char kbuf[256];
    size_t len;
    ssize_t ret;

    if (unlikely(!ksu_selinux_hide_enabled))
        goto passthrough;
    if (current_uid().val < 10000)
        goto passthrough;

    ino = file_inode(file)->i_ino;
    if (ino != KSU_SEL_CONTEXT_INO && ino != KSU_SEL_ACCESS_INO)
        goto passthrough;

    len = size < sizeof(kbuf) - 1 ? size : sizeof(kbuf) - 1;
    if (copy_from_user(kbuf, ubuf, len))
        goto passthrough;
    kbuf[len] = 0;

    if (ino == KSU_SEL_CONTEXT_INO)
        goto passthrough;

    ret = orig_sel_write(file, ubuf, size, pos);
    if (ret <= 0)
        return ret;

    {
        bool deny = false;
        u32 deny_mask = 0;
        char scon[128], tcon[128];
        unsigned int tclass_num;

        if (sscanf(kbuf, "%127s %127s %u", scon, tcon, &tclass_num) == 3) {
            if (ksu_should_hide_context(scon) || ksu_should_hide_context(tcon)) {
                pr_info_ratelimited("selinux_hide: blocked access context: %.40s\n", kbuf);
                return -EINVAL;
            }
            if (ksu_is_dirty_access_query(scon, tcon))
                deny = true;
            /* Hide system_server -> system_server:process execmem (class 2, bit 25) from app UIDs */
            if (!strcmp(scon, "u:r:system_server:s0") &&
                !strcmp(tcon, "u:r:system_server:s0") &&
                tclass_num == 2)
                deny_mask |= (1U << 25);
        }

        ksu_fix_access_response(file->private_data, deny, deny_mask);
    }

    return ret;

passthrough:
    return orig_sel_write(file, ubuf, size, pos);
}

static ssize_t (*orig_proc_pid_attr_write)(struct file *, const char __user *, size_t, loff_t *) __read_mostly;
static struct file_operations *g_proc_attr_fops;

static __nocfi ssize_t ksu_proc_pid_attr_write(struct file *file, const char __user *ubuf, size_t size, loff_t *pos)
{
    char kbuf[128];
    size_t len;
    const char *attr_name;

    if (unlikely(!ksu_selinux_hide_enabled))
        goto passthrough;
    if (current_uid().val < 10000)
        goto passthrough;

    attr_name = file->f_path.dentry->d_name.name;
    if (!attr_name || strcmp(attr_name, "current"))
        goto passthrough;

    len = size < sizeof(kbuf) - 1 ? size : sizeof(kbuf) - 1;
    if (copy_from_user(kbuf, ubuf, len))
        goto passthrough;
    kbuf[len] = '\0';

    if (ksu_should_hide_context(kbuf)) {
#if KSU_HAS_SELINUX_STATE
        u32 dummy_sid = 0;
        static const char dummy_ctx[] = "u:r:ksu_nonexistent_sentinel:s0";
        security_context_to_sid(&selinux_state, dummy_ctx,
                                sizeof(dummy_ctx) - 1, &dummy_sid, GFP_KERNEL);
#endif
        pr_info_ratelimited("selinux_hide: attr/current blocked: %.40s\n", kbuf);
        return -EINVAL;
    }

passthrough:
    return orig_proc_pid_attr_write(file, ubuf, size, pos);
}

static void ksu_hook_proc_attr_write(void)
{
    /* Handled directly inside selinux_setprocattr via ksu_selinux_hide_is_hidden_ctx */
}

static void ksu_hook_transaction_write(void)
{
    struct file_operations *fops;
    int ret;

    if (orig_sel_write)
        return;

    fops = ksu_resolve_fops("/sys/fs/selinux/context");
    if (!fops || !fops->write)
        return;

    g_sel_context_fops = fops;
    orig_sel_write = fops->write;
    ret = ksu_patch_fops_slot((void **)&fops->write, ksu_sel_write);
    if (ret)
        pr_warn("selinux_hide: patch write failed: %d\n", ret);
}

static struct page *ksu_fake_status_page __read_mostly = NULL;
static int (*orig_status_open)(struct inode *, struct file *) = NULL;
static struct file_operations *g_status_fops;

static struct page *ksu_get_real_status_page(void)
{
#if KSU_HAS_SELINUX_STATE
    return selinux_kernel_status_page(&selinux_state);
#else
    return selinux_kernel_status_page();
#endif
}

static int ksu_prepare_fake_status_page(void)
{
    struct page *real, *fake;
    struct selinux_kernel_status *rs, *fs;

    if (READ_ONCE(ksu_fake_status_page))
        return 0;

    real = ksu_get_real_status_page();
    if (!real)
        return -ENOENT;

    fake = alloc_page(GFP_KERNEL | __GFP_ZERO);
    if (!fake)
        return -ENOMEM;

    rs = page_address(real);
    fs = page_address(fake);
    memcpy(fs, rs, sizeof(*fs));

    fs->enforcing = 1;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
    fs->sequence    = 4;
    fs->policyload  = 1;
#else
    fs->sequence    = 0;
    fs->policyload  = 0;
#endif

    smp_store_release(&ksu_fake_status_page, fake);
    pr_info_ratelimited("selinux_hide: fake status ready seq=%d\n", fs->sequence);
    return 0;
}

static __nocfi int ksu_status_open(struct inode *inode, struct file *filp)
{
    if (likely(ksu_selinux_hide_enabled && current_uid().val >= 10000)) {
        struct page *fp = smp_load_acquire(&ksu_fake_status_page);
        if (fp) {
            filp->private_data = fp;
            return 0;
        }
    }
    return orig_status_open(inode, filp);
}

static void ksu_hook_status_open(void)
{
    struct file_operations *fops;
    int ret;

    if (orig_status_open)
        return;

    fops = ksu_resolve_fops("/sys/fs/selinux/status");
    if (!fops || !fops->open)
        return;

    g_status_fops = fops;
    orig_status_open = fops->open;
    ret = ksu_patch_fops_slot((void **)&fops->open, ksu_status_open);
    if (ret)
        pr_warn("selinux_hide: patch status open failed: %d\n", ret);
}

static int selinux_hide_get(u64 *v)
{
    *v = ksu_selinux_hide_enabled ? 1 : 0;
    return 0;
}

static int selinux_hide_set(u64 v)
{
    ksu_selinux_hide_enabled = !!v;
    pr_info_ratelimited("selinux_hide: enabled=%d\n", ksu_selinux_hide_enabled);
    return 0;
}

static const struct ksu_feature_handler selinux_hide_handler = {
    .feature_id = KSU_FEATURE_SELINUX_HIDE,
    .name = "selinux_hide",
    .get_handler = selinux_hide_get,
    .set_handler = selinux_hide_set,
};

static int ksu_selinux_hide_init_thread(void *data)
{
    int tries = 0;

    set_user_nice(current, 19);

    ksu_selinux_hide_add_type(KERNEL_SU_DOMAIN);
    ksu_selinux_hide_add_type(KERNEL_SU_FILE);
    ksu_selinux_hide_add_rule(KERNEL_SU_DOMAIN, KERNEL_SU_FILE);
    ksu_selinux_hide_add_type("magisk");
    ksu_selinux_hide_add_type("magisk_file");
    ksu_selinux_hide_add_type("droidspacesd");
    ksu_selinux_hide_add_type("droidspaces");
    ksu_selinux_hide_add_type("lsposed_file");
    ksu_selinux_hide_add_type("xposed_data");
    ksu_selinux_hide_add_type("xposed_file");
    ksu_selinux_hide_add_type("adbroot");
    ksu_selinux_hide_add_type("msd_app");
    ksu_selinux_hide_add_type("msd_daemon");

try_again:
    if (ksu_prepare_fake_status_page()) {
        if (++tries > 10)
            goto skip_status;
        msleep(1000);
        goto try_again;
    }
    ksu_hook_status_open();

skip_status:
    ksu_hook_transaction_write();
    ksu_hook_proc_attr_write();
    return 0;
}

void ksu_selinux_hide_handle_second_stage(void)
{
    if (!READ_ONCE(ksu_fake_status_page))
        ksu_prepare_fake_status_page();
    ksu_hook_status_open();
    ksu_hook_transaction_write();
    ksu_hook_proc_attr_write();
}

void ksu_selinux_hide_handle_post_fs_data(void)
{
    if (!READ_ONCE(ksu_fake_status_page))
        ksu_prepare_fake_status_page();
    ksu_hook_status_open();
    ksu_hook_transaction_write();
    ksu_hook_proc_attr_write();
}

void __init ksu_selinux_hide_init(void)
{
    if (ksu_register_feature_handler(&selinux_hide_handler))
        pr_err("selinux_hide: register feature failed\n");

    kthread_run(ksu_selinux_hide_init_thread, NULL, "ksu_selinux_hide");
}

void __exit ksu_selinux_hide_exit(void)
{
    ksu_unregister_feature_handler(KSU_FEATURE_SELINUX_HIDE);

    mutex_lock(&ksu_hide_list_mutex);
    ksu_rcu_replace(&ksu_hide_type_list, NULL);
    ksu_rcu_replace(&ksu_hide_rule_list, NULL);
    mutex_unlock(&ksu_hide_list_mutex);

    if (g_sel_context_fops && orig_sel_write)
        ksu_patch_fops_slot((void **)&g_sel_context_fops->write, orig_sel_write);
    if (g_status_fops && orig_status_open)
        ksu_patch_fops_slot((void **)&g_status_fops->open, orig_status_open);
    if (g_proc_attr_fops && orig_proc_pid_attr_write) {
        ksu_patch_fops_slot((void **)&g_proc_attr_fops->write, orig_proc_pid_attr_write);
        orig_proc_pid_attr_write = NULL;
    }
}
