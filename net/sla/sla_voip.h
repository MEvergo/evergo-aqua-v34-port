/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * SLA VoIP capture state.
 *
 * RECONSTRUCTED from the target ROM's proprietary vendor sla.ko disassembly;
 * this is not the OEM's original source and the OEM module is not
 * redistributable. The struct layout (8 bytes) and capture/take semantics
 * match the observed stock behavior: first qualifying outbound UDP packet
 * latches {IPv4 daddr, raw network-order dport}, and reading the state
 * consumes it.
 */
#ifndef SLA_VOIP_H
#define SLA_VOIP_H

/* The stock module stores an IPv4 destination and raw UDP dport in eight bytes. */
struct sla_voip_state {
    unsigned int address;
    unsigned short port;
    unsigned short reserved;
};

static inline void sla_voip_capture(struct sla_voip_state *state,
                                    unsigned char enabled, unsigned int uid,
                                    unsigned char protocol, unsigned int socket_uid,
                                    unsigned int address, unsigned short raw_dport)
{
    if (enabled && uid && protocol == 17 && socket_uid == uid &&
        !state->address && raw_dport != 0x3500) {
        state->port = raw_dport;
        state->address = address;
    }
}

static inline struct sla_voip_state sla_voip_take(struct sla_voip_state *state)
{
    struct sla_voip_state snapshot = *state;

    state->address = 0;
    state->port = 0;
    state->reserved = 0;
    return snapshot;
}

#endif
