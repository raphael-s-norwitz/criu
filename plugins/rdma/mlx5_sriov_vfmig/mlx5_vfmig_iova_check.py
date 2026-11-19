#!/usr/bin/env python3
"""Report which SET_TRACKED iova_bits this host's mlx5 VFs can take.

MLX5_VFMIG_IOC_SET_TRACKED reserves a VF's fixed IOVA window
[2^(bits-1), 2^bits) in the VF's DMA-IOMMU domain. An image replays only
onto a VF tracked with the bits it was saved with, so an orchestrator
should pick, at first provisioning, bits that every host the workload may
move to can take: run this with --json on each host, then --intersect the
results.

The kernel works the platform's answer out when it probes each PF and
lists it in /sys/class/mlx5_vfmig/mlx5_vfmig!<PF>/iova_bits: the windows
the IOMMU aperture and bus DMA limit reach and no PCI host-bridge window
or IOMMU reserved region of the PF overlaps. What it cannot see from the
PF, this adds for every VF that exists:
  - reserved regions firmware scopes to that VF alone (its IOMMU group's
    reserved_regions); a window one overlaps is dropped;
  - an IOMMU group that is not a DMA domain (iommu=pt), which SET_TRACKED
    refuses until the group's type is set to DMA or DMA-FQ;
  - an IOMMU group shared with other devices, whose DMA is not visible.
IOVAs still mapped in a VF's domain are not checked; an unbound VF has
none unless a driver leaked them. SET_TRACKED has the final say.

--allocations also lists each VF's reserved regions and, where the IOMMU
driver exposes them, its live IOVA mappings: Intel VT-d with
CONFIG_INTEL_IOMMU_DEBUGFS, read as root from
/sys/kernel/debug/iommu/intel/<bdf>/domain_translation_struct. Listed
only; the verdicts do not use them.

Read-only. Needs only the Python 3 standard library.
"""

import argparse
import json
import os
import re
import sys

# MLX5_VFMIG_IOVA_BITS_MIN and MLX5_VFMIG_IOVA_BITS_DEFAULT in
# <linux/mlx5_vfmig.h>.
IOVA_BITS_MIN = 34
IOVA_BITS_MAX = 39

CLASS_DIR = "/sys/class/mlx5_vfmig"


class Host:
    """Paths of the host being checked: the live one, or a captured tree."""

    def __init__(self, root):
        self.root = root

    def path(self, p):
        return os.path.join(self.root, p.lstrip("/")) if self.root else p

    def read(self, p):
        try:
            with open(self.path(p)) as f:
                return f.read().strip()
        except OSError:
            return None

    def link_base(self, p):
        try:
            return os.path.basename(os.readlink(self.path(p)))
        except OSError:
            return None


def window(bits):
    return 1 << (bits - 1), (1 << bits) - 1


def in_windows(start, last):
    return [b for b in range(IOVA_BITS_MAX, IOVA_BITS_MIN - 1, -1)
            if start <= window(b)[1] and last >= window(b)[0]]


def human(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return ("%d %s" if n == int(n) else "%.1f %s") % (n, unit)
        n /= 1024.0


def find_pfs(host):
    prefix = "mlx5_vfmig!"
    try:
        names = os.listdir(host.path(CLASS_DIR))
    except OSError:
        return []
    return sorted(n[len(prefix):] for n in names if n.startswith(prefix))


def kernel_bits(host, pf):
    """The PF's sysfs iova_bits as a list, or None if the kernel has no such file."""
    text = host.read("%s/mlx5_vfmig!%s/iova_bits" % (CLASS_DIR, pf))
    if text is None:
        return None
    return sorted((int(b) for b in text.split()), reverse=True)


def vfs_of(host, pf):
    vfs, i = [], 0
    while True:
        vf = host.link_base("/sys/bus/pci/devices/%s/virtfn%d" % (pf, i))
        if not vf:
            return vfs
        vfs.append(vf)
        i += 1


def check_vf(host, bdf):
    v = {"bdf": bdf, "group": None, "group_type": None, "reserved": [], "notes": []}
    grp = host.link_base("/sys/bus/pci/devices/%s/iommu_group" % bdf)
    if not grp:
        v["notes"].append("no IOMMU group: its DMA is untranslated, SET_TRACKED cannot reserve a window")
        return v
    gdir = "/sys/kernel/iommu_groups/" + grp
    v["group"] = grp
    v["group_type"] = host.read(gdir + "/type")
    if v["group_type"] and not v["group_type"].startswith("DMA"):
        v["notes"].append("IOMMU group %s is type %s: write DMA or DMA-FQ to its type file while "
                          "the VF is unbound before SET_TRACKED" % (grp, v["group_type"]))
    try:
        members = os.listdir(host.path(gdir + "/devices"))
    except OSError:
        members = []
    if len(members) > 1:
        v["notes"].append("IOMMU group %s is shared with %d other device(s), whose DMA is not visible"
                          % (grp, len(members) - 1))
    for line in (host.read(gdir + "/reserved_regions") or "").splitlines():
        f = line.split()
        if len(f) >= 3:
            start, last = int(f[0], 16), int(f[1], 16)
            v["reserved"].append({"start": "0x%x" % start, "last": "0x%x" % last, "type": f[2],
                                  "in_windows": in_windows(start, last)})
    return v


# A leaf line of domain_translation_struct is the IOVA PFN, then one entry per
# table level walked: PML5E PML4E PDPE are always printed, PDE and PTE only
# when the walk reached them, so the entry count gives the leaf's size.
_DTS_LINE_RE = re.compile(r"^0x([0-9a-f]+) \|\s*(.*)$")
_DTS_LEAF_BYTES = {3: 1 << 30, 4: 1 << 21, 5: 1 << 12}


def read_mappings(host, dev):
    """Coalesced IOVA ranges mapped in @dev's DMA domain, from Intel IOMMU
    debugfs, or a string saying why they cannot be read."""
    dbg = "/sys/kernel/debug/iommu/intel"
    try:
        with open(host.path("%s/%s/domain_translation_struct" % (dbg, dev))) as f:
            text = f.read()
    except PermissionError:
        return "needs root (debugfs)"
    except OSError:
        if not os.path.isdir(host.path(dbg)):
            return ("no Intel IOMMU debugfs at %s (needs CONFIG_INTEL_IOMMU_DEBUGFS and a "
                    "mounted debugfs)" % dbg)
        return "no domain_translation_struct for %s" % dev
    ranges = []
    for line in text.splitlines():
        m = _DTS_LINE_RE.match(line)
        size = _DTS_LEAF_BYTES.get(len(m.group(2).split())) if m else None
        if not size:
            continue
        start = int(m.group(1), 16) << 12
        if ranges and ranges[-1][1] + 1 == start:
            ranges[-1][1] = start + size - 1
        else:
            ranges.append([start, start + size - 1])
    return [{"start": "0x%x" % s, "last": "0x%x" % e, "bytes": e - s + 1,
             "in_windows": in_windows(s, e)} for s, e in ranges]


def evaluate(host, pf, allocations):
    r = {"pf": pf, "kernel_iova_bits": kernel_bits(host, pf), "vfs": [], "dropped": {},
         "notes": []}
    if r["kernel_iova_bits"] is None:
        r["notes"].append("no %s/mlx5_vfmig!%s/iova_bits: the kernel predates IOVA window "
                          "selection" % (CLASS_DIR, pf))
        r["acceptable_iova_bits"] = []
        return r
    for bdf in vfs_of(host, pf):
        v = check_vf(host, bdf)
        for reg in v["reserved"]:
            for b in reg["in_windows"]:
                if b in r["kernel_iova_bits"] and b not in r["dropped"]:
                    r["dropped"][b] = "%s reserved region [%s, %s] (%s, group %s)" % (
                        bdf, reg["start"], reg["last"], reg["type"], v["group"])
        if allocations:
            v["mapped"] = read_mappings(host, bdf)
        else:
            del v["reserved"]
        r["vfs"].append(v)
    if not r["vfs"]:
        r["notes"].append("no VFs exist: reserved regions scoped to a single VF are checked once "
                          "SR-IOV is enabled")
    r["acceptable_iova_bits"] = [b for b in r["kernel_iova_bits"] if b not in r["dropped"]]
    return r


def print_text(r):
    print("PF %s" % r["pf"])
    if r["kernel_iova_bits"] is not None:
        print("  kernel lists: %s" % (" ".join(map(str, r["kernel_iova_bits"])) or "none"))
    for b in sorted(r["dropped"], reverse=True):
        lo, hi = window(b)
        print("  %d bits [0x%x, 0x%x): dropped, overlaps %s" % (b, lo, hi + 1, r["dropped"][b]))
    print("  acceptable iova_bits: %s" % (" ".join(map(str, r["acceptable_iova_bits"])) or "none"))
    for n in r["notes"]:
        print("  note: %s" % n)
    for v in r["vfs"]:
        for n in v["notes"]:
            print("  note: VF %s: %s" % (v["bdf"], n))
        if "reserved" in v:
            print("  VF %s (group %s, %s):" % (v["bdf"], v["group"], v["group_type"]))
            for reg in v["reserved"]:
                where = (" (in the %s-bit window)" % ",".join(map(str, reg["in_windows"]))
                         if reg["in_windows"] else "")
                print("    reserved [%18s, %18s]  %s%s" % (reg["start"], reg["last"], reg["type"],
                                                         where))
            m = v["mapped"]
            if isinstance(m, str):
                print("    mappings not available: %s" % m)
                continue
            print("    mapped: %d range(s), %s" % (len(m), human(sum(x["bytes"] for x in m))))
            for x in m:
                where = (" (in the %s-bit window)" % ",".join(map(str, x["in_windows"]))
                         if x["in_windows"] else "")
                print("    mapped   [%18s, %18s]  %s%s" % (x["start"], x["last"],
                                                         human(x["bytes"]), where))
    print()


def intersect(files):
    """iova_bits every PF in every --json result in @files accepts."""
    common, seen = None, []
    for path in files:
        with open(path) as f:
            doc = json.load(f)
        for r in doc.get("pfs", []):
            seen.append("%s %s" % (path, r["pf"]))
            bits = set(r.get("acceptable_iova_bits", []))
            common = bits if common is None else common & bits
    return sorted(common or [], reverse=True), seen


def main():
    ap = argparse.ArgumentParser(
        description="Report which MLX5_VFMIG_IOC_SET_TRACKED iova_bits (%d..%d) the VFs of each "
                    "PF can take on this host, from the kernel's per-PF sysfs list plus what "
                    "only the VFs show. An image replays only onto a VF tracked with the same "
                    "iova_bits, so pick bits acceptable on every host a workload may migrate to."
                    % (IOVA_BITS_MIN, IOVA_BITS_MAX),
        epilog="Exit status: 0 every PF (or, with --intersect, every result) shares an "
               "acceptable iova_bits; 1 not; 2 usage error, no PF found, or a kernel without "
               "the sysfs list.")
    ap.add_argument("-p", "--pf", action="append", metavar="BDF",
                    help="PF to check (repeatable). Default: every PF with an mlx5_vfmig device.")
    ap.add_argument("--json", action="store_true", help="print JSON instead of text")
    ap.add_argument("--allocations", action="store_true",
                    help="also list each VF's reserved regions and mapped IOVA ranges (Intel "
                         "IOMMU debugfs, root); listed only")
    ap.add_argument("--intersect", nargs="+", metavar="JSON",
                    help="instead of checking this host, print the iova_bits every PF in these "
                         "--json results accepts")
    ap.add_argument("--root", metavar="DIR", default="",
                    help="check a captured tree: read /sys under DIR")
    args = ap.parse_args()

    if args.intersect:
        common, seen = intersect(args.intersect)
        if args.json:
            json.dump({"acceptable_iova_bits": common, "pfs": seen}, sys.stdout, indent=2)
            print()
        else:
            print("acceptable on all %d PF(s): %s" % (len(seen), " ".join(map(str, common)) or "none"))
        return 0 if common else 1

    host = Host(args.root)
    pfs = sorted(args.pf) if args.pf else find_pfs(host)
    if not pfs:
        print("mlx5_vfmig_iova_check: no PF with an mlx5_vfmig device (is mlx5_core loaded with "
              "vfmig support? pass --pf BDF)", file=sys.stderr)
        return 2

    results = [evaluate(host, pf, args.allocations) for pf in pfs]
    if args.json:
        json.dump({"iova_bits_range": [IOVA_BITS_MIN, IOVA_BITS_MAX], "pfs": results},
                  sys.stdout, indent=2)
        print()
    else:
        for r in results:
            print_text(r)
    if any(r["kernel_iova_bits"] is None for r in results):
        return 2
    return 0 if all(r["acceptable_iova_bits"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
