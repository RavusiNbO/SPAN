// span_nf.c: mirrors incoming IPv4 packets from source to destination.
// Configure: echo "eth0 eth1" | sudo tee /proc/span_nf
// Read stats: cat /proc/span_nf

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/if_ether.h>
#include <linux/if.h>
#include <linux/atomic.h>
#include <linux/string.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <linux/spinlock.h>
#include <net/net_namespace.h>

#define PROC_NAME "span_nf"
#define PROC_BUFSZ (IFNAMSIZ * 2 + 4)

MODULE_AUTHOR("Fakhretdinov Ravil");
MODULE_DESCRIPTION("Mirror incoming IPv4 packets using Netfilter");
MODULE_LICENSE("GPL");

static char srcname[IFNAMSIZ];
static char destname[IFNAMSIZ];
static struct net_device *dest_dev;
static DEFINE_SPINLOCK(config_lock);

static atomic64_t mirrored_packets = ATOMIC64_INIT(0);
static atomic64_t mirrored_bytes   = ATOMIC64_INIT(0);
static atomic64_t send_errors      = ATOMIC64_INIT(0);

static unsigned int span_hook(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    struct sk_buff *copy;
    struct net_device *out_dev;
    unsigned long flags;
    int mac_len, rc;
    unsigned int packet_len;
    bool source_matches;

    (void)priv;
    if (!skb || !state || !state->in)
        return NF_ACCEPT;

    spin_lock_irqsave(&config_lock, flags);
    source_matches = srcname[0] && strcmp(state->in->name, srcname) == 0;
    out_dev = source_matches ? dest_dev : NULL;
    if (out_dev)
        dev_hold(out_dev);
    spin_unlock_irqrestore(&config_lock, flags);

    if (!source_matches || !out_dev)
        return NF_ACCEPT;

    /* This example mirrors IPv4 ingress only, not ARP, IPv6, or egress. */
    if (skb->protocol != htons(ETH_P_IP)) {
        dev_put(out_dev);
        return NF_ACCEPT;
    }

    if (!skb_mac_header_was_set(skb) ||
        !skb_network_header_was_set(skb)) {
        atomic64_inc(&send_errors);
        dev_put(out_dev);
        return NF_ACCEPT;
    }

    mac_len = (int)(skb_network_header(skb) - skb_mac_header(skb));
    if (mac_len < ETH_HLEN || mac_len > skb_headroom(skb)) {
        atomic64_inc(&send_errors);
        dev_put(out_dev);
        return NF_ACCEPT;
    }

    copy = skb_copy(skb, GFP_ATOMIC);
    if (!copy) {
        atomic64_inc(&send_errors);
        dev_put(out_dev);
        return NF_ACCEPT;
    }

    if (mac_len > skb_headroom(copy)) {
        atomic64_inc(&send_errors);
        kfree_skb(copy);
        dev_put(out_dev);
        return NF_ACCEPT;
    }

    skb_push(copy, mac_len);
    skb_reset_mac_header(copy);
    copy->dev = out_dev;
    copy->pkt_type = PACKET_OUTGOING;
    packet_len = copy->len;

    /* dev_queue_xmit() consumes copy; do not free it after this call. */
    rc = dev_queue_xmit(copy);
    if (net_xmit_eval(rc)) {
        atomic64_inc(&send_errors);
    } else {
        atomic64_inc(&mirrored_packets);
        atomic64_add(packet_len, &mirrored_bytes);
    }

    dev_put(out_dev);
    return NF_ACCEPT;
}

static struct nf_hook_ops span_ops = {
    .hook     = span_hook,
    .pf       = NFPROTO_IPV4,
    .hooknum  = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int span_proc_show(struct seq_file *m, void *v)
{
    char src[IFNAMSIZ], dst[IFNAMSIZ];
    unsigned long flags;

    (void)v;
    spin_lock_irqsave(&config_lock, flags);
    strscpy(src, srcname, sizeof(src));
    strscpy(dst, destname, sizeof(dst));
    spin_unlock_irqrestore(&config_lock, flags);

    seq_printf(m, "source=%s\n", src[0] ? src : "(not set)");
    seq_printf(m, "destination=%s\n", dst[0] ? dst : "(not set)");
    seq_printf(m, "mirrored_packets=%lld\n",
               (long long)atomic64_read(&mirrored_packets));
    seq_printf(m, "mirrored_bytes=%lld\n",
               (long long)atomic64_read(&mirrored_bytes));
    seq_printf(m, "send_errors=%lld\n",
               (long long)atomic64_read(&send_errors));
    seq_puts(m, "Write two interface names: <source> <destination>\n");
    return 0;
}

static int span_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, span_proc_show, NULL);
}

static ssize_t span_proc_write(struct file *file, const char __user *ubuf,
                               size_t count, loff_t *ppos)
{
    char buf[PROC_BUFSZ];
    char new_src[IFNAMSIZ], new_dst[IFNAMSIZ];
    struct net_device *new_src_dev, *new_dst_dev, *old_dst_dev;
    unsigned long flags;
    int parsed;

    (void)file;
    (void)ppos;

    if (!count || count >= sizeof(buf))
        return -EINVAL;
    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;
    buf[count] = '\0';

    parsed = sscanf(buf, "%15s %15s", new_src, new_dst);
    if (parsed != 2)
        return -EINVAL;
    if (!strcmp(new_src, new_dst))
        return -EINVAL;

    new_src_dev = dev_get_by_name(&init_net, new_src);
    if (!new_src_dev) {
        pr_err("span_nf: source interface '%s' not found\n", new_src);
        return -ENODEV;
    }

    new_dst_dev = dev_get_by_name(&init_net, new_dst);
    if (!new_dst_dev) {
        dev_put(new_src_dev);
        pr_err("span_nf: destination interface '%s' not found\n", new_dst);
        return -ENODEV;
    }
    dev_put(new_src_dev);

    /* The hook takes its own device reference under this same lock. */
    spin_lock_irqsave(&config_lock, flags);
    old_dst_dev = dest_dev;
    dest_dev = new_dst_dev;
    strscpy(srcname, new_src, sizeof(srcname));
    strscpy(destname, new_dst, sizeof(destname));
    spin_unlock_irqrestore(&config_lock, flags);

    if (old_dst_dev)
        dev_put(old_dst_dev);

    pr_info("span_nf: mirroring IPv4 ingress %s -> %s\n", new_src, new_dst);
    return count;
}

static const struct proc_ops span_proc_ops = {
    .proc_open    = span_proc_open,
    .proc_read    = seq_read,
    .proc_write   = span_proc_write,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static int __init load_mod(void)
{
    int ret = nf_register_net_hook(&init_net, &span_ops);
    if (ret) {
        pr_err("span_nf: nf_register_net_hook failed: %d\n", ret);
        return ret;
    }

    if (!proc_create(PROC_NAME, 0600, NULL, &span_proc_ops)) {
        nf_unregister_net_hook(&init_net, &span_ops);
        pr_err("span_nf: failed to create /proc/%s\n", PROC_NAME);
        return -ENOMEM;
    }

    pr_info("span_nf: loaded; configure through /proc/%s\n", PROC_NAME);
    return 0;
}

static void __exit unload_mod(void)
{
    struct net_device *old_dst_dev;
    unsigned long flags;

    remove_proc_entry(PROC_NAME, NULL);
    nf_unregister_net_hook(&init_net, &span_ops);

    spin_lock_irqsave(&config_lock, flags);
    old_dst_dev = dest_dev;
    dest_dev = NULL;
    srcname[0] = '\0';
    destname[0] = '\0';
    spin_unlock_irqrestore(&config_lock, flags);

    if (old_dst_dev)
        dev_put(old_dst_dev);

    pr_info("span_nf: packets=%lld bytes=%lld errors=%lld\n",
            (long long)atomic64_read(&mirrored_packets),
            (long long)atomic64_read(&mirrored_bytes),
            (long long)atomic64_read(&send_errors));
}

module_init(load_mod);
module_exit(unload_mod);
