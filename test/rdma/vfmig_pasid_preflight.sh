#!/bin/bash
# INTERNAL VALIDATION ONLY -- drop before upstream PR.
#
# Read-only preflight: can this host give a ConnectX VF a second, explicitly
# mapped PASID address space (a paging domain attached with
# iommu_attach_device_pasid()) next to its ordinary DMA domain?
#
# Nothing here writes sysfs, PCI config space or driver state. Run as root
# for the full picture: PCI extended capabilities (PASID/ATS/PRI), dmesg and
# IOMMU debugfs are not readable otherwise; those checks report UNKNOWN.
#
# Usage: vfmig_pasid_preflight.sh [--vf BDF] [--src KERNEL_SRC] [--out DIR]
#   --vf   VF to qualify (default: every ConnectX VF found)
#   --src  kernel source tree matching the running kernel (default: none,
#          source checks skipped)
#   --out  directory for raw captures (default: ./pasid-preflight-<host>-<ts>)
#
# It also lists the PFs on which restorable (vfmig-trackable) VFs could be
# created. The firmware migration caps are confirmed from the kernel log: a
# VF tracked on the PF this boot proves them.
#
# Verdicts: YES (shown), NO (shown absent / rejected), UNKNOWN (could not be
# read or is not observable from here), NOT_TESTED (needs an active test).

set -u
export LC_ALL=C

VFS=()
SRC=""
OUT=""
while [ $# -gt 0 ]; do
	case "$1" in
	--vf) VFS+=("$2"); shift 2 ;;
	--src) SRC="$2"; shift 2 ;;
	--out) OUT="$2"; shift 2 ;;
	-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

OUT=${OUT:-./pasid-preflight-$(hostname -s)-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT" || exit 1
REPORT="$OUT/report.txt"
: > "$REPORT"

ROOT=0
[ "$(id -u)" = 0 ] && ROOT=1
KLOG=""

declare -A VERDICT
VERDICT_ORDER=()

say() { echo "$*" | tee -a "$REPORT"; }
sayin() { tee -a "$REPORT"; }
section() { say ""; say "== $* =="; }
verdict() {	# key value reason
	[ -n "${VERDICT[$1]+x}" ] || VERDICT_ORDER+=("$1")
	VERDICT[$1]="$2  ($3)"
	say "  -> $1: $2 ($3)"
}
capture() {	# file cmd...
	local f="$OUT/$1"; shift
	"$@" > "$f" 2>&1
}
join() { local s="" x; for x in "$@"; do s="${s:+$s; }$x"; done; echo "$s"; }
bit() { echo $(( ($1 >> $2) & 1 )); }
field() { echo $(( ($1 >> $2) & $3 )); }

kconfig() {
	local cfg
	if [ -r /proc/config.gz ]; then
		zcat /proc/config.gz
	elif [ -r "/boot/config-$(uname -r)" ]; then
		cat "/boot/config-$(uname -r)"
	elif [ -n "$SRC" ] && [ -r "$SRC/.config" ]; then
		cat "$SRC/.config"
	fi
}

# ---------------------------------------------------------------------------
section "Host"
say "kernel:   $(uname -r)"
say "cmdline:  $(cat /proc/cmdline)"
VIRT=$(systemd-detect-virt 2>/dev/null || echo unknown)
say "virt:     $VIRT"
say "dmi:      $(cat /sys/class/dmi/id/sys_vendor 2>/dev/null) / $(cat /sys/class/dmi/id/product_name 2>/dev/null)"
say "cpu:      $(awk -F': ' '/^vendor_id/{print $2; exit}' /proc/cpuinfo)"
say "root:     $ROOT"
[ "$ROOT" = 1 ] || say "  (not root: PCI extended caps, dmesg and debugfs will be UNKNOWN)"

# ---------------------------------------------------------------------------
section "Kernel configuration"
CFG=$(kconfig)
if [ -z "$CFG" ]; then
	say "  no kernel config found (/proc/config.gz, /boot/config-*, --src/.config)"
else
	for k in IOMMU_API IOMMU_SVA IOMMU_IOPF IOMMUFD IOMMUFD_TEST VFIO_PCI \
		 PCI_ATS PCI_PRI PCI_PASID \
		 INTEL_IOMMU INTEL_IOMMU_SVM INTEL_IOMMU_SCALABLE_MODE_DEFAULT_ON \
		 AMD_IOMMU ARM_SMMU_V3 ARM_SMMU_V3_SVA VIRTIO_IOMMU \
		 IOMMU_DEFAULT_PASSTHROUGH IOMMU_DEFAULT_DMA_LAZY IOMMU_DEFAULT_DMA_STRICT \
		 MLX5_CORE MLX5_INFINIBAND MLX5_VFMIG; do
		v=$(echo "$CFG" | grep -E "^CONFIG_$k=" | cut -d= -f2)
		say "  CONFIG_$k=${v:-n}"
	done
	echo "$CFG" > "$OUT/kconfig.txt"
fi
CMDLINE=$(cat /proc/cmdline)
case "$CMDLINE" in
*intel_iommu=*sm_off*) say "  cmdline forces intel scalable mode OFF (intel_iommu=sm_off)" ;;
*intel_iommu=*sm_on*) say "  cmdline requests intel scalable mode ON (intel_iommu=sm_on)" ;;
esac
case "$CMDLINE" in
*iommu=pt*|*iommu.passthrough=1*) say "  cmdline: default domains are identity (iommu=pt); a tracked vfmig VF uses its own managed domain" ;;
esac
[ -e /dev/iommu ] && say "  /dev/iommu present (iommufd loaded)" || say "  /dev/iommu absent (iommufd not loaded or not built)"

# ---------------------------------------------------------------------------
section "IOMMU hardware"
IOMMU_KIND=none
HW_PASID=UNKNOWN
HW_PASID_WHY="no IOMMU capability registers readable"
HW_PASID_BITS=0

for d in /sys/class/iommu/*; do
	[ -e "$d" ] || continue
	n=$(basename "$d")
	if [ -r "$d/intel-iommu/ecap" ]; then
		IOMMU_KIND=intel
		cap=$((16#$(cat "$d/intel-iommu/cap")))
		ecap=$((16#$(cat "$d/intel-iommu/ecap")))
		ver=$(cat "$d/intel-iommu/version")
		say "  $n: Intel VT-d version $ver cap=0x$(printf %x $cap) ecap=0x$(printf %x $ecap)"
		say "    caching_mode=$(bit $cap 7) (1 = emulated/virtual IOMMU)"
		say "    ecap: SMTS(scalable mode)=$(bit $ecap 43) PASID=$(bit $ecap 40) PSS=$(field $ecap 35 31)$([ "$(bit $ecap 40)" = 1 ] && echo " (width $(( $(field $ecap 35 31) + 1 )) bits)")"
		say "          FLTS(first stage)=$(bit $ecap 47) SLTS(second stage)=$(bit $ecap 46) NEST=$(bit $ecap 26) PRS=$(bit $ecap 29) DT(ATS)=$(bit $ecap 2) PT=$(bit $ecap 6)"
		if [ "$(bit $ecap 43)" = 1 ] && [ "$(bit $ecap 40)" = 1 ]; then
			HW_PASID=YES
			HW_PASID_BITS=$(( $(field $ecap 35 31) + 1 ))
			HW_PASID_WHY="VT-d scalable mode + PASID, $HW_PASID_BITS-bit"
		elif [ "$HW_PASID" != YES ]; then
			HW_PASID=NO
			HW_PASID_WHY="$n: ecap SMTS=$(bit $ecap 43) PASID=$(bit $ecap 40)"
			[ "$(bit $cap 7)" = 1 ] && HW_PASID_WHY="$HW_PASID_WHY; caching mode set, so this is a vIOMMU: the hypervisor must enable scalable mode + PASID"
		fi
	elif [ -r "$d/amd-iommu/features" ]; then
		IOMMU_KIND=amd
		f=$(cat "$d/amd-iommu/features")
		efr=$((16#${f%%:*}))
		say "  $n: AMD-Vi efr:efr2=$f"
		say "    PPRSup=$(bit $efr 1) GTSup=$(bit $efr 4) PASmax=$(field $efr 32 31) GIOSup=$(bit $efr 48)"
		if [ "$(bit $efr 4)" = 1 ] && [ "$(field $efr 32 31)" -gt 0 ]; then
			HW_PASID=YES
			HW_PASID_BITS=$(( $(field $efr 32 31) + 1 ))
			HW_PASID_WHY="AMD-Vi GTSup + PASmax $HW_PASID_BITS-bit"
		else
			HW_PASID=NO
			HW_PASID_WHY="$n: GTSup=$(bit $efr 4) PASmax=$(field $efr 32 31)"
		fi
	else
		say "  $n: no decodable capability attributes"
	fi
done
if [ "$IOMMU_KIND" = none ]; then
	if ls /sys/bus/platform/drivers/arm-smmu-v3/ 2>/dev/null | grep -q .; then
		IOMMU_KIND=smmuv3
		HW_PASID_WHY="SMMUv3 SSID width is only logged by the driver; see dmesg"
	elif ls /sys/bus/virtio/drivers/virtio_iommu/ 2>/dev/null | grep -q virtio; then
		IOMMU_KIND=virtio
		HW_PASID=NO
		HW_PASID_WHY="virtio-iommu has no PASID support"
	fi
fi
say "  iommu kind: $IOMMU_KIND"
verdict "iommu_hw_pasid" "$HW_PASID" "$HW_PASID_WHY"

if [ "$ROOT" = 1 ]; then
	dmesg > "$OUT/dmesg.txt" 2>&1
	KLOG="$OUT/dmesg.txt"
	if ! grep -qE '^\[ *0\.' "$KLOG" && command -v journalctl >/dev/null; then
		journalctl -k -b --no-pager > "$OUT/journal_kernel.txt" 2>&1
		KLOG="$OUT/journal_kernel.txt"
		say "  dmesg ring has rotated past boot; using journalctl -k -b"
	fi
	say "  boot log (IOMMU/PASID lines):"
	grep -iE 'DMAR|IOMMU|AMD-Vi|smmu|pasid|scalable|SVM|ssid' "$KLOG" \
		| grep -v vfmig_iova | head -40 | sed 's/^/    /' | sayin
	if [ -d /sys/kernel/debug/iommu ]; then
		capture debugfs_iommu_ls.txt ls -R /sys/kernel/debug/iommu
		say "  IOMMU debugfs listed in debugfs_iommu_ls.txt"
	fi
fi

# ---------------------------------------------------------------------------
section "ConnectX functions"
PFS=()
ALL_VFS=()
for dev in /sys/bus/pci/devices/*; do
	[ "$(cat "$dev/vendor")" = 0x15b3 ] || continue
	bdf=$(basename "$dev")
	if [ -e "$dev/physfn" ]; then
		ALL_VFS+=("$bdf")
	else
		PFS+=("$bdf")
	fi
done
[ ${#VFS[@]} -eq 0 ] && VFS=("${ALL_VFS[@]}")

fn_info() {	# bdf
	local dev=/sys/bus/pci/devices/$1 drv grp ib fw net
	drv=$(basename "$(readlink "$dev/driver" 2>/dev/null)" 2>/dev/null)
	grp=$(basename "$(readlink "$dev/iommu_group" 2>/dev/null)" 2>/dev/null)
	ib=$(ls "$dev/infiniband" 2>/dev/null | head -1)
	fw=""
	[ -n "$ib" ] && fw=$(cat "/sys/class/infiniband/$ib/fw_ver" 2>/dev/null)
	net=$(ls "$dev/net" 2>/dev/null | tr '\n' ' ')
	say "  $1 [$(lspci -s "$1" -mm 2>/dev/null | awk -F'"' '{print $6}')] driver=${drv:-none} iommu_group=${grp:-none} ib=${ib:-none} fw=${fw:-?} net=${net:-none}"
}

for pf in "${PFS[@]}"; do
	fn_info "$pf"
	dev=/sys/bus/pci/devices/$pf
	say "    sriov_numvfs=$(cat "$dev/sriov_numvfs" 2>/dev/null || echo n/a) sriov_totalvfs=$(cat "$dev/sriov_totalvfs" 2>/dev/null || echo n/a)"
	if command -v devlink >/dev/null; then
		capture "devlink_info_$pf.txt" devlink dev info "pci/$pf"
		grep -E 'board\.id|fw\.psid|fw\.version' "$OUT/devlink_info_$pf.txt" | awk '!seen[$1]++' \
			| sed 's/^ */    devlink: /' | sayin
	fi
done
for vf in "${ALL_VFS[@]}"; do
	fn_info "$vf"
	say "    physfn=$(basename "$(readlink /sys/bus/pci/devices/$vf/physfn)")"
done
[ ${#PFS[@]} -eq 0 ] && say "  no ConnectX (15b3) functions found"
[ ${#ALL_VFS[@]} -eq 0 ] && say "  no ConnectX VFs exist; PF-only results below"

# ---------------------------------------------------------------------------
section "PCIe PASID / ATS / PRI capabilities"
DEV_PASID=UNKNOWN
DEV_PASID_WHY="needs root to read PCI extended capabilities"
DEV_PASID_EN=UNKNOWN
declare -A PF_PASID PF_ACS
pcicaps() {	# bdf
	local f="$OUT/lspci_vvv_$1.txt"
	lspci -vvv -s "$1" > "$f" 2>&1
	if grep -qE 'Process Address Space ID|Address Translation Service|Page Request Interface' "$f"; then
		grep -A2 -E 'Process Address Space ID|Address Translation Service|Page Request Interface' "$f" \
			| sed 's/^\s*/    /'
	else
		echo "    no PASID, ATS or PRI capability; capabilities present:"
		grep -oE 'Capabilities: \[[0-9a-f v]+\] [^:,]+' "$f" | sed 's/^Capabilities: /      /'
	fi
}
if [ "$ROOT" = 1 ]; then
	DEV_PASID=NO
	DEV_PASID_WHY="no PF advertises a PASID capability"
	for pf in "${PFS[@]}"; do
		say "  PF $pf:"
		pcicaps "$pf" | sayin
		f="$OUT/lspci_vvv_$pf.txt"
		PF_PASID[$pf]=NO
		grep -q 'Access Control Services' "$f" && PF_ACS[$pf]=YES || PF_ACS[$pf]=NO
		if grep -q 'Process Address Space ID' "$f"; then
			PF_PASID[$pf]=YES
			w=$(grep -A1 'Process Address Space ID' "$f" | grep -oE 'Max PASID Width: [0-9a-f]+' | awk '{print $4}')
			en=$(grep -A2 'Process Address Space ID' "$f" | grep -oE 'PASIDCtl: Enable[+-]' | tail -c2)
			DEV_PASID=YES
			DEV_PASID_WHY="PF $pf PASID cap, Max PASID Width $w (lspci prints hex)"
			[ "$en" = "+" ] && DEV_PASID_EN=YES || DEV_PASID_EN=NO
		fi
	done
	for vf in "${VFS[@]}"; do
		say "  VF $vf (a VF has no PASID capability of its own; it uses the PF's):"
		pcicaps "$vf" | sayin
	done
	if [ "$DEV_PASID" = NO ] && [ "$VIRT" != none ]; then
		DEV_PASID_WHY="$DEV_PASID_WHY to this guest; the hypervisor may hide it (QEMU vfio hides PASID unless the vIOMMU supports it)"
		grep -q 'Address Translation Service' "$OUT/lspci_vvv_${PFS[0]}.txt" 2>/dev/null ||
			DEV_PASID_WHY="$DEV_PASID_WHY; ATS is hidden too, so the physical device is unknown: run this on the hypervisor"
	fi
fi
verdict "device_pasid_cap" "$DEV_PASID" "$DEV_PASID_WHY"
verdict "device_pasid_enabled" "$DEV_PASID_EN" "PF PASIDCtl Enable bit; normally set by the IOMMU driver at probe when the IOMMU supports PASID"

# ---------------------------------------------------------------------------
section "Selected VF IOMMU association"
for vf in "${VFS[@]}"; do
	dev=/sys/bus/pci/devices/$vf
	g=$(readlink "$dev/iommu_group" 2>/dev/null)
	if [ -z "$g" ]; then
		say "  $vf: no IOMMU group"
		continue
	fi
	gn=$(basename "$g")
	say "  $vf: group $gn type=$(cat /sys/kernel/iommu_groups/$gn/type 2>/dev/null) members=$(ls /sys/kernel/iommu_groups/$gn/devices | tr '\n' ' ')"
	say "    iommu=$(basename "$(readlink "$dev/iommu" 2>/dev/null)" 2>/dev/null) reserved_regions:"
	sed 's/^/      /' /sys/kernel/iommu_groups/$gn/reserved_regions | sayin
done
[ ${#VFS[@]} -eq 0 ] && say "  (no VF selected)"

# ---------------------------------------------------------------------------
section "Candidate PFs for restorable VFs"
say "  A restorable VF needs: a PF bound to mlx5_core with the vfmig control"
say "  device, SR-IOV room, legacy eswitch, firmware 'migration' and"
say "  'vhca_resource_manager' caps, and its own IOMMU group on a managed DMA"
say "  domain. The PASID column is extra: what a PASID design would need on top."
CANDIDATES=()
for pf in "${PFS[@]}"; do
	dev=/sys/bus/pci/devices/$pf
	no=(); unk=()
	say "  PF $pf:"

	drv=$(basename "$(readlink "$dev/driver" 2>/dev/null)" 2>/dev/null)
	say "    driver:          ${drv:-none}"
	[ "$drv" = mlx5_core ] || no+=("not bound to mlx5_core")

	if [ -e "/dev/mlx5_vfmig/$pf" ]; then
		say "    vfmig device:    /dev/mlx5_vfmig/$pf"
	else
		say "    vfmig device:    absent"
		no+=("no /dev/mlx5_vfmig/$pf (CONFIG_MLX5_VFMIG or PF init)")
	fi

	tot=$(cat "$dev/sriov_totalvfs" 2>/dev/null || echo 0)
	num=$(cat "$dev/sriov_numvfs" 2>/dev/null || echo 0)
	say "    sr-iov:          $num of $tot VFs enabled"
	[ "$tot" -gt 0 ] || no+=("no SR-IOV (sriov_totalvfs=0)")
	[ "$num" -gt 0 ] && say "    (sriov_numvfs can only change via 0; existing VFs are recycled, not re-created)"

	mode=$(devlink dev eswitch show "pci/$pf" 2>/dev/null |
	       awk '{for (i = 1; i < NF; i++) if ($i == "mode") { print $(i + 1); exit }}')
	say "    eswitch mode:    ${mode:-unknown}"
	case "$mode" in
	legacy) ;;
	"") unk+=("eswitch mode unreadable") ;;
	*) unk+=("eswitch mode $mode is untested; the vfmig tests use legacy") ;;
	esac

	# The kernel's own view comes first: vfmig refuses to make a VF
	# migratable unless the PF has 'migration' and 'vhca_resource_manager',
	# so a VF tracked on this PF this boot proves both.
	kev=UNKNOWN
	if [ -n "$KLOG" ]; then
		if grep -qE "mlx5_core $pf: vfmig: PF firmware does not advertise" "$KLOG"; then
			kev=NO
			say "    kernel log:      $(grep -m1 -oE "vfmig: PF firmware does not advertise.*" "$KLOG")"
			no+=("kernel reports missing firmware migration caps")
		elif grep -qE "mlx5_core $pf: vfmig: vf [0-9]+ tracked=1" "$KLOG"; then
			kev=YES
			say "    kernel log:      a VF was tracked on this PF this boot (firmware migration caps present)"
		else
			say "    kernel log:      no vfmig tracking on this PF this boot"
		fi
	fi

	if [ "$kev" = UNKNOWN ]; then
		why="no VF tracked on this PF this boot"
		[ -n "$KLOG" ] || why="kernel log needs root"
		unk+=("firmware migration caps unconfirmed ($why)")
	fi

	grp=$(basename "$(readlink "$dev/iommu_group" 2>/dev/null)" 2>/dev/null)
	if [ -z "$grp" ]; then
		say "    iommu:           no group"
		no+=("no IOMMU translation (migratable VFs need a managed DMA domain)")
	else
		gtype=$(cat /sys/kernel/iommu_groups/$grp/type 2>/dev/null)
		say "    iommu:           PF group $grp type $gtype; ACS ${PF_ACS[$pf]:-UNKNOWN}"
		case "$gtype" in
		identity) say "    (VFs default to identity too; set each VF group's type to DMA before SET_TRACKED, as the test loop does)" ;;
		esac
		[ "${PF_ACS[$pf]:-UNKNOWN}" = NO ] && unk+=("no ACS on the PF: VFs may share an IOMMU group, and tracking needs one group per VF")
	fi

	for vf in "${ALL_VFS[@]}"; do
		[ "$(basename "$(readlink /sys/bus/pci/devices/$vf/physfn)")" = "$pf" ] || continue
		vid=""
		vfg=$(basename "$(readlink "/sys/bus/pci/devices/$vf/iommu_group" 2>/dev/null)" 2>/dev/null)
		vft=$(cat /sys/kernel/iommu_groups/$vfg/type 2>/dev/null)
		vfn=$(ls /sys/kernel/iommu_groups/$vfg/devices 2>/dev/null | wc -l)
		vfd=$(basename "$(readlink "/sys/bus/pci/devices/$vf/driver" 2>/dev/null)" 2>/dev/null)
		line="    VF $vf: driver=${vfd:-none} group=${vfg:-none} type=${vft:-?} group_members=$vfn"
		for i in /sys/bus/pci/devices/$pf/virtfn*; do
			[ "$(basename "$(readlink -f "$i")")" = "$vf" ] && vid=${i##*virtfn}
		done
		if [ -n "$vid" ]; then
			line="$line vf_id=$vid"
			[ -n "$KLOG" ] && grep -qE "mlx5_core $pf: vfmig: vf $vid tracked=1" "$KLOG" &&
				line="$line (tracked this boot)"
		fi
		say "$line"
	done

	pasid=${PF_PASID[$pf]:-UNKNOWN}
	say "    PASID (extra):   PF capability $pasid; IOMMU $HW_PASID"

	if [ ${#no[@]} -gt 0 ]; then
		say "    => NOT A CANDIDATE: $(join "${no[@]}")"
	elif [ ${#unk[@]} -gt 0 ]; then
		say "    => POSSIBLE, unconfirmed: $(join "${unk[@]}")"
		CANDIDATES+=("$pf(unconfirmed)")
	else
		say "    => CANDIDATE: up to $tot restorable VFs ($num enabled now)"
		CANDIDATES+=("$pf")
	fi
done
verdict "restorable_vf_pfs" "${CANDIDATES[*]:-none}" "PFs that pass the vfmig tracking prerequisites; PASID is separate"

# ---------------------------------------------------------------------------
section "Kernel PASID attach support (source)"
SRC_ATTACH=UNKNOWN
SRC_WHY="no --src given"
if [ -n "$SRC" ] && [ -d "$SRC/drivers/iommu" ]; then
	sv=$(make -s -C "$SRC" kernelversion 2>/dev/null)
	say "  source: $SRC ($sv; running $(uname -r))"
	has() { grep -qE "$2" "$SRC/$1" 2>/dev/null && echo yes || echo no; }
	say "  iommu_attach_device_pasid():        $(has drivers/iommu/iommu.c 'int iommu_attach_device_pasid')"
	say "  IOMMU_HWPT_ALLOC_PASID uapi:        $(has include/uapi/linux/iommufd.h 'IOMMU_HWPT_ALLOC_PASID')"
	say "  vfio PASID attach uapi:             $(has include/uapi/linux/vfio.h 'VFIO_DEVICE_ATTACH_PASID')"
	case "$IOMMU_KIND" in
	intel)
		p=$(has drivers/iommu/intel/iommu.c '\.set_dev_pasid\s*=\s*intel_iommu_set_dev_pasid')
		say "  intel paging domain .set_dev_pasid: $p (needs scalable mode + ecap.PASID at runtime)"
		SRC_ATTACH=$([ "$p" = yes ] && echo YES || echo NO)
		SRC_WHY="intel_iommu_set_dev_pasid on paging domains: $p" ;;
	amd)
		p=$(grep -n 'set_dev_pasid' "$SRC"/drivers/iommu/amd/*.c | grep -v -E 'sva|blocked' | head -1)
		say "  amd paging domain .set_dev_pasid:   ${p:-no (only SVA and blocked domains implement it)}"
		SRC_ATTACH=$([ -n "$p" ] && echo YES || echo NO)
		SRC_WHY="AMD: ${p:+paging set_dev_pasid present}${p:-only SVA/blocked domains take a PASID; mapped paging domains cannot be attached}" ;;
	smmuv3)
		p=$(has drivers/iommu/arm/arm-smmu-v3/arm-smmu-v3.c 'set_dev_pasid\s*=\s*arm_smmu_s1_set_dev_pasid')
		say "  smmuv3 S1 paging .set_dev_pasid:    $p (S1 domains only)"
		SRC_ATTACH=$([ "$p" = yes ] && echo YES || echo NO)
		SRC_WHY="arm_smmu_s1_set_dev_pasid: $p" ;;
	virtio)
		SRC_ATTACH=NO; SRC_WHY="virtio-iommu implements no set_dev_pasid" ;;
	*)
		SRC_WHY="no recognised IOMMU" ;;
	esac
	n=$(grep -rniw pasid "$SRC"/include/linux/mlx5 "$SRC"/drivers/net/ethernet/mellanox/mlx5/core "$SRC"/drivers/infiniband/hw/mlx5 2>/dev/null | wc -l)
	say "  mlx5 references to PASID (ifc/core/ib): $n"
fi
verdict "kernel_paging_pasid_attach" "$SRC_ATTACH" "$SRC_WHY"

# ---------------------------------------------------------------------------
section "Active attachment test feasibility"
RUNTIME=NO
RUNTIME_WHY=""
[ "$HW_PASID" = YES ] || RUNTIME_WHY="IOMMU does not advertise PASID ($HW_PASID)"
[ "$DEV_PASID" = YES ] || RUNTIME_WHY="${RUNTIME_WHY:+$RUNTIME_WHY; }PF PASID capability $DEV_PASID"
[ "$SRC_ATTACH" = NO ] && RUNTIME_WHY="${RUNTIME_WHY:+$RUNTIME_WHY; }kernel paging-domain PASID attach unsupported"
[ -z "$RUNTIME_WHY" ] && { RUNTIME=POSSIBLE; RUNTIME_WHY="all prerequisites shown; needs an mlx5 hook on a dedicated test VF"; }
verdict "attach_test_possible" "$RUNTIME" "$RUNTIME_WHY"
verdict "attach_demonstrated" "NOT_TESTED" "iommu_attach_device_pasid() must be called by the VF's bound driver; no hook exists yet"
verdict "tagged_dma_demonstrated" "NOT_TESTED" "no documented mlx5 interface found to tag VF DMA with an OS-chosen PASID"

# ---------------------------------------------------------------------------
section "Summary"
for k in "${VERDICT_ORDER[@]}"; do
	say "  $(printf '%-28s' "$k") ${VERDICT[$k]}"
done
say ""
say "raw captures in $OUT"
