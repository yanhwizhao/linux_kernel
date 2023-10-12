/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_KVM_EXPORTED_TDP_H
#define _ASM_X86_KVM_EXPORTED_TDP_H
#define PT64_ROOT_MAX_LEVEL 5

#include <linux/kvm_types.h>
/**
 * struct kvm_exported_tdp_meta_vmx - Intel specific meta data format of TDP
 *                                    page tables exported by KVM.
 *
 * Importers of KVM exported TDPs can decode meta data of the page tables with
 * this structure.
 *
 * @type:                Type defined across platforms to identify hardware
 *                       platform of a KVM exported TDP. Importers of KVM
 *                       exported TDP need to first check the type before
 *                       decoding page table meta data.
 * @level:               Levels of the TDP exported by KVM.
 * @root_hpa:            HPA of the root page of TDP exported by KVM.
 * @max_huge_page_level: Max huge page level allowed on the TDP exported by KVM.
 * @rsvd_bits_mask:      The must-be-zero bits of leaf and non-leaf PTEs.
 *                       rsvd_bits_mask[0] or rsvd_bits_mask[1] is selected by
 *                       bit 7 or a PTE.
 *                       This field is provided as a way for importers to check
 *                       if the must-be-zero bits from KVM is compatible to the
 *                       importer side. KVM will ensure that the must-be-zero
 *                       bits must not be set even for software purpose.
 *                       (e.g. on Intel platform, bit 11 is usually used by KVM
 *                       to identify a present SPTE, though bit 11 is ignored by
 *                       EPT. However, Intel vt-d requires the bit 11 to be 0.
 *                       Before importing KVM TDP, Intel vt-d driver needs to
 *                       check if bit 11 is set in the must-be-zero bits by KVM
 *                       to avoid possible DMAR fault.)
 */
struct kvm_exported_tdp_meta_vmx {
	enum kvm_exported_tdp_type type;
	int level;
	hpa_t root_hpa;
	int max_huge_page_level;
	u64 rsvd_bits_mask[2][PT64_ROOT_MAX_LEVEL];
};

#endif
