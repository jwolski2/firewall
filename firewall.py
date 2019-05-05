from bcc import BPF

import time
import sys

ctx_type = 'xdp_md'
device = 'wlp2s0'
flags = 0
return_code = 'XDP_PASS'

# Configure and Load BPF program.
b = BPF(text="""
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>

BPF_TABLE("percpu_array", uint32_t, long, drops, 256);

int xdp_prog(struct CTXTYPE *ctx) {
    void *data = (void*)(long)ctx->data;
    struct ethhdr *eth = data;

    // TODO: Not entirely sure what this is protecting.
    void *data_end = (void*)(long)ctx->data_end;
    uint64_t offset = data + sizeof(*eth);
    if (offset > data_end) {
        return XDP_PASS;
    }

    // Ignore if not IP packet.
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Parse IP packet.
    struct iphdr *ip = offset;
    if ((void*)&ip[1] > data_end) {
        return XDP_PASS;
    }

    int proto = ip->protocol;
    long *value = drops.lookup(&proto);
    if (!value) {
        return XDP_PASS;
    }

    *value += 1;

    return RETURNCODE;
}
""", cflags=['-w', '-DRETURNCODE=%s' % return_code, '-DCTXTYPE=%s' % ctx_type])

xdp_prog = b.load_func('xdp_prog', BPF.XDP)

b.attach_xdp(device, xdp_prog, flags)

counts = [0] * 256
drops = b['drops']

while 1:
    try:
        # Print number of packets seen per CPU.
        for k in drops.keys():
            val = drops.sum(k).value
            i = k.value
            if val:
                delta = val - counts[i]
                counts[i] = val
                print("{}: {} pkt/s".format(i, delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print('Removing filter from device')
        break

# Cleanup before exiting.
b.remove_xdp(device, flags)
