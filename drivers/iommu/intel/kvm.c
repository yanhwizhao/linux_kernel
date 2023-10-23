// SPDX-License-Identifier: GPL-2.0
#include <linux/iommu.h>
#include <asm/kvm_exported_tdp.h>
#include "iommu.h"

/**
 * Check IOMMU hardware Snoop related caps
 *
 * - force_snooping:             Force snoop cpu caches per current KVM implementation.
 * - scalable-mode:              To enable PGSNP bit in PASIDTE to overwrite SNP
 *                               bit (bit 11) in stage 2 leaves.
 * - paging structure coherency: As KVM will not call clflush_cache_range()
 */
static bool is_coherency(struct intel_iommu *iommu)
{
	return ecap_sc_support(iommu->ecap) && sm_supported(iommu) &&
	       iommu_paging_structure_coherency(iommu);
}

static bool is_iommu_cap_compatible_to_kvm_domain(struct dmar_domain *domain,
						  struct intel_iommu *iommu)
{
	if (!is_coherency(iommu))
		return false;

	if (domain->iommu_superpage > fls(cap_super_page_val(iommu->cap)))
		return false;

	if (domain->agaw > iommu->agaw || domain->agaw > cap_mgaw(iommu->cap))
		return false;

	return true;
}

/*
 * Cache coherency is always enforced in KVM domain.
 * IOMMU hardware caps will be checked to allow the cache coherency before
 * device attachment to the KVM domain.
 */
static bool kvm_domain_enforce_cache_coherency(struct iommu_domain *domain)
{
	return true;
}

static const struct iommu_domain_ops intel_kvm_domain_ops = {
	.free			= intel_iommu_domain_free,
	.enforce_cache_coherency = kvm_domain_enforce_cache_coherency,
};

struct iommu_domain *
intel_iommu_domain_alloc_kvm(struct device *dev, u32 flags, const void *data)
{
	bool request_nest_parent = flags & IOMMU_HWPT_ALLOC_NEST_PARENT;
	const struct kvm_exported_tdp_meta_vmx *tdp = data;
	struct dmar_domain *dmar_domain;
	struct iommu_domain *domain;
	struct intel_iommu *iommu;
	int adjust_width;

	iommu = device_to_iommu(dev, NULL, NULL);

	if (!iommu)
		return ERR_PTR(-ENODEV);
	/*
	 * In theroy, a KVM domain can be nested as a parent domain to a user
	 * domain. Turn it off as we don't want to handle cases like IO page
	 * fault on nested domain for now.
	 */
	if ((request_nest_parent)) {
		pr_err("KVM domain does not work as nested parent currently\n");
		return ERR_PTR(-EOPNOTSUPP);
	}

	if (!tdp || tdp->type != KVM_TDP_TYPE_EPT) {
		pr_err("No meta data or wrong KVM TDP type\n");
		return ERR_PTR(-EINVAL);
	}

	if (tdp->level != 4 && tdp->level != 5) {
		pr_err("Unsupported KVM TDP level %d in IOMMU\n", tdp->level);
		return ERR_PTR(-EOPNOTSUPP);
	}

	dmar_domain = alloc_domain(IOMMU_DOMAIN_KVM);
	if (!dmar_domain)
		return ERR_PTR(-ENOMEM);

	if (dmar_domain->use_first_level)
		WARN_ON("KVM domain is applying to IOMMU flpt\n");

	domain = &dmar_domain->domain;
	domain->ops = &intel_kvm_domain_ops;
	domain->type = IOMMU_DOMAIN_KVM;

	/* read dmar domain meta data from "tdp" */
	dmar_domain->gaw = tdp->level == 4 ? ADDR_WIDTH_4LEVEL : ADDR_WIDTH_5LEVEL;
	adjust_width = guestwidth_to_adjustwidth(dmar_domain->gaw);
	dmar_domain->agaw = width_to_agaw(adjust_width);
	dmar_domain->iommu_superpage = tdp->max_huge_page_level - 1;
	dmar_domain->max_addr = (1 << dmar_domain->gaw);
	dmar_domain->pgd = phys_to_virt(tdp->root_hpa);

	dmar_domain->nested_parent = false;
	dmar_domain->dirty_tracking = false;

	/*
	 * force_snooping and paging strucure coherency in KVM domain
	 * IOMMU hareware cap will be checked before device attach
	 */
	dmar_domain->force_snooping = true;
	dmar_domain->iommu_coherency = true;

	/* no need to let iommu_map/unmap see pgsize_bitmap */
	domain->pgsize_bitmap = 0;

	/* force aperture */
	domain->geometry.aperture_start = 0;
	domain->geometry.aperture_end = __DOMAIN_MAX_ADDR(dmar_domain->gaw);
	domain->geometry.force_aperture = true;

	if (!is_iommu_cap_compatible_to_kvm_domain(dmar_domain, iommu)) {
		pr_err("Unsupported KVM TDP\n");
		kfree(dmar_domain);
		return ERR_PTR(-EOPNOTSUPP);
	}

	return domain;
}
