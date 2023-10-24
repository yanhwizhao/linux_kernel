// SPDX-License-Identifier: GPL-2.0-only
#include <linux/iommu.h>
#include <uapi/linux/iommufd.h>
#include <linux/kvm_tdp_fd.h>

#include "../iommu-priv.h"
#include "iommufd_private.h"

static void iommufd_kvmtdp_invalidate(void *data,
				      unsigned long start, unsigned long size)
{
	void (*invalidate_fn)(struct iommu_domain *domain,
			      unsigned long iova, unsigned long size);
	struct iommufd_hw_pagetable *hwpt = data;

	if (!hwpt || !hwpt_is_kvm(hwpt))
		return;

	invalidate_fn = hwpt->domain->ops->cache_invalidate_kvm;

	if (!invalidate_fn)
		return;

	invalidate_fn(hwpt->domain, start, size);

}

struct kvm_tdp_importer_ops iommufd_import_ops = {
	.invalidate = iommufd_kvmtdp_invalidate,
};

static inline int kvmtdp_register(struct kvm_tdp_fd *tdp_fd, void *data)
{
	if (!tdp_fd->ops->register_importer || !tdp_fd->ops->register_importer)
		return -EOPNOTSUPP;

	return tdp_fd->ops->register_importer(tdp_fd, &iommufd_import_ops, data);
}

static inline void kvmtdp_unregister(struct kvm_tdp_fd *tdp_fd)
{
	WARN_ON(!tdp_fd->ops->unregister_importer);

	tdp_fd->ops->unregister_importer(tdp_fd, &iommufd_import_ops);
}

static inline void *kvmtdp_get_metadata(struct kvm_tdp_fd *tdp_fd)
{
	if (!tdp_fd->ops->get_metadata)
		return ERR_PTR(-EOPNOTSUPP);

	return tdp_fd->ops->get_metadata(tdp_fd);
}

/*
 * Get KVM TDP FD object and ensure tdp_fd->ops is available
 */
static inline struct kvm_tdp_fd *kvmtdp_get(int fd)
{
	struct kvm_tdp_fd *tdp_fd = NULL;
	struct kvm_tdp_fd *(*get_func)(int fd) = NULL;
	void (*put_func)(struct kvm_tdp_fd *) = NULL;

	get_func = symbol_get(kvm_tdp_fd_get);

	if (!get_func)
		goto out;

	put_func = symbol_get(kvm_tdp_fd_put);
	if (!put_func)
		goto out;

	tdp_fd = get_func(fd);
	if (!tdp_fd)
		goto out;

	if (tdp_fd->ops) {
		/* success */
		goto out;
	}

	put_func(tdp_fd);
	tdp_fd = NULL;

out:
	if (get_func)
		symbol_put(kvm_tdp_fd_get);

	if (put_func)
		symbol_put(kvm_tdp_fd_put);

	return tdp_fd;
}

static void kvmtdp_put(struct kvm_tdp_fd *tdp_fd)
{
	void (*put_func)(struct kvm_tdp_fd *) = NULL;

	put_func = symbol_get(kvm_tdp_fd_put);
	WARN_ON(!put_func);

	put_func(tdp_fd);

	symbol_put(kvm_tdp_fd_put);
}

void iommufd_hwpt_kvm_destroy(struct iommufd_object *obj)
{
	struct kvm_tdp_fd *tdp_fd;
	struct iommufd_hwpt_kvm *hwpt_kvm =
		container_of(obj, struct iommufd_hwpt_kvm, common.obj);

	if (hwpt_kvm->common.domain)
		iommu_domain_free(hwpt_kvm->common.domain);

	tdp_fd = hwpt_kvm->context;
	kvmtdp_unregister(tdp_fd);
	kvmtdp_put(tdp_fd);
}

void iommufd_hwpt_kvm_abort(struct iommufd_object *obj)
{
	iommufd_hwpt_kvm_destroy(obj);
}

struct iommufd_hwpt_kvm *
iommufd_hwpt_kvm_alloc(struct iommufd_ctx *ictx,
		       struct iommufd_device *idev, u32 flags,
		       const struct iommu_hwpt_kvm_info *kvm_data)
{

	const struct iommu_ops *ops = dev_iommu_ops(idev->dev);
	struct iommufd_hwpt_kvm *hwpt_kvm;
	struct iommufd_hw_pagetable *hwpt;
	struct kvm_tdp_fd *tdp_fd;
	void *meta_data;
	int rc;

	if (!ops->domain_alloc_kvm)
		return ERR_PTR(-EOPNOTSUPP);

	if (kvm_data->fd < 0)
		return ERR_PTR(-EINVAL);

	tdp_fd = kvmtdp_get(kvm_data->fd);
	if (!tdp_fd)
		return ERR_PTR(-EOPNOTSUPP);

	meta_data = kvmtdp_get_metadata(tdp_fd);
	if (!meta_data || IS_ERR(meta_data)) {
		rc = -EFAULT;
		goto out_put_tdp;
	}

	hwpt_kvm = __iommufd_object_alloc(ictx, hwpt_kvm, IOMMUFD_OBJ_HWPT_KVM,
					  common.obj);
	if (IS_ERR(hwpt_kvm)) {
		rc = PTR_ERR(hwpt_kvm);
		goto out_put_tdp;
	}

	hwpt_kvm->context = tdp_fd;
	hwpt = &hwpt_kvm->common;

	hwpt->domain = ops->domain_alloc_kvm(idev->dev, flags, meta_data);
	if (IS_ERR(hwpt->domain)) {
		rc = PTR_ERR(hwpt->domain);
		hwpt->domain = NULL;
		goto out_abort;
	}

	rc = kvmtdp_register(tdp_fd, hwpt);
	if (rc)
		goto out_abort;

	return hwpt_kvm;

out_abort:
	iommufd_object_abort_and_destroy(ictx, &hwpt->obj);
out_put_tdp:
	kvmtdp_put(tdp_fd);
	return ERR_PTR(rc);
}
