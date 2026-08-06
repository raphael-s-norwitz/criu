#ifndef __CR_VFMIG_INTERNAL_H__
#define __CR_VFMIG_INTERNAL_H__

/*
 * Cross-file declarations shared between the rdma_mlx5_vfmig plugin
 * sources. Strictly NOT a public surface -- this header lives next to
 * the .c files that use it, never installed. It grows one section at a
 * time as each milestone adds a source module.
 */

#include <stdbool.h>

/*
 * Process-global activation flag. Set true by init() once presence
 * detection lands and finds at least one tracked VF; read by the
 * hooks added in later commits to short-circuit cheaply on a host
 * that has no mlx5_vfmig cdevs at all. The skeleton leaves it false.
 */
extern bool vfmig_active;

#endif /* __CR_VFMIG_INTERNAL_H__ */
