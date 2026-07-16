#ifndef __CR_VFMIG_BARRIER_WIRE_H__
#define __CR_VFMIG_BARRIER_WIRE_H__

/*
 * On-the-wire contract for the mlx5_vfmig cross-host datapath barrier.
 * Shared between the plugin (vfmig_barrier.c) and out-of-tree peers
 * that speak the same rendezvous -- notably the test peer stub
 * (test/rdma/vfmig_barrier_peer.c) that stands in for a second host in
 * single-host CRIU harnesses. Keep this header dependency-free (fixed-
 * width ints only) so both sides agree byte-for-byte and neither drifts.
 *
 * Each barrier edge exchanges exactly one struct vfmig_barrier_msg in
 * each direction over a TCP connection; a side is satisfied once every
 * listed peer has sent a matching {magic, version, phase, session}.
 */

#include <stdint.h>

#define VFMIG_BARRIER_MAGIC   0x564d4231u	/* "VMB1" */
#define VFMIG_BARRIER_VERSION 1

/* Fixed-layout wire record exchanged both ways on each edge. */
struct vfmig_barrier_msg {
	uint32_t magic;
	uint16_t version;
	uint16_t listen_port;
	char	 phase[4];		/* "D1" / "R1", NUL-padded */
	char	 session[64];		/* NUL-padded */
	uint8_t	 vf_uuid[16];
	char	 listen_ip[64];		/* sender's listen ip, NUL-padded */
};

#endif /* __CR_VFMIG_BARRIER_WIRE_H__ */
