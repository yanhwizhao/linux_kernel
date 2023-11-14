// SPDX-License-Identifier: GPL-2.0-only
/*
 * KVM TDP FD
 *
 */
#include <linux/anon_inodes.h>
#include <uapi/linux/kvm.h>
#include <linux/kvm_host.h>

#include "tdp_fd.h"

static inline int is_tdp_fd_file(struct file *file);
static const struct file_operations kvm_tdp_fd_fops;
static const struct kvm_exported_tdp_ops exported_tdp_ops;

struct kvm_tdp_importer {
	struct kvm_tdp_importer_ops *ops;
	void *data;
	struct list_head node;
};
static void kvm_tdp_unregister_all_importers(struct kvm_exported_tdp *tdp);

int kvm_create_tdp_fd(struct kvm *kvm, struct kvm_create_tdp_fd *ct)
{
	struct kvm_exported_tdp *tdp;
	struct kvm_tdp_fd *tdp_fd;
	int as_id = ct->as_id;
	int ret, fd;

	if (as_id >= KVM_ADDRESS_SPACE_NUM || ct->pad || ct->mode)
		return -EINVAL;

	/* for each address space, only one exported tdp is allowed */
	spin_lock(&kvm->exported_tdplist_lock);
	list_for_each_entry(tdp, &kvm->exported_tdp_list, list_node) {
		if (tdp->as_id != as_id)
			continue;

		spin_unlock(&kvm->exported_tdplist_lock);
		return -EEXIST;
	}
	spin_unlock(&kvm->exported_tdplist_lock);

	tdp_fd = kzalloc(sizeof(*tdp_fd), GFP_KERNEL_ACCOUNT);
	if (!tdp)
		return -ENOMEM;

	tdp = kzalloc(sizeof(*tdp), GFP_KERNEL_ACCOUNT);
	if (!tdp) {
		kfree(tdp_fd);
		return -ENOMEM;
	}
	tdp_fd->priv = tdp;
	tdp->tdp_fd = tdp_fd;
	tdp->as_id = as_id;

	if (!kvm_get_kvm_safe(kvm)) {
		ret = -ENODEV;
		goto out;
	}
	tdp->kvm = kvm;
	ret = kvm_arch_exported_tdp_init(kvm, tdp);
	if (ret)
		goto out;

	INIT_LIST_HEAD(&tdp->importers);
	spin_lock_init(&tdp->importer_lock);

	tdp_fd->file = anon_inode_getfile("tdp_fd", &kvm_tdp_fd_fops,
					tdp_fd, O_RDWR | O_CLOEXEC);
	if (!tdp_fd->file) {
		ret = -EFAULT;
		goto out_uninit;
	}

	fd = get_unused_fd_flags(O_RDWR | O_CLOEXEC);
	if (fd < 0)
		goto out_uninit;

	fd_install(fd, tdp_fd->file);
	ct->fd = fd;
	tdp_fd->ops = &exported_tdp_ops;

	spin_lock(&kvm->exported_tdplist_lock);
	list_add(&tdp->list_node, &kvm->exported_tdp_list);
	spin_unlock(&kvm->exported_tdplist_lock);
	return 0;

out_uninit:
	if (tdp_fd->file)
		fput(tdp_fd->file);

	kvm_arch_exported_tdp_destroy(tdp);
out:
	if (tdp->kvm)
		kvm_put_kvm_no_destroy(tdp->kvm);
	kfree(tdp);
	kfree(tdp_fd);
	return ret;
}

static int kvm_tdp_fd_release(struct inode *inode, struct file *file)
{
	struct kvm_exported_tdp *tdp;
	struct kvm_tdp_fd *tdp_fd;

	if (!is_tdp_fd_file(file))
		return -EINVAL;

	tdp_fd = file->private_data;
	tdp = tdp_fd->priv;

	if (WARN_ON(!tdp || !tdp->kvm))
		return -EFAULT;

	spin_lock(&tdp->kvm->exported_tdplist_lock);
	list_del(&tdp->list_node);
	spin_unlock(&tdp->kvm->exported_tdplist_lock);

	kvm_tdp_unregister_all_importers(tdp);
	kvm_arch_exported_tdp_destroy(tdp);
	kvm_put_kvm(tdp->kvm);
	kfree(tdp);
	kfree(tdp_fd);
	return 0;
}

static long kvm_tdp_fd_ioctl(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	/* Do not support ioctl currently. May add it in future */
	return -ENODEV;
}

static int kvm_tdp_fd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -ENODEV;
}

static const struct file_operations kvm_tdp_fd_fops = {
	.unlocked_ioctl = kvm_tdp_fd_ioctl,
	.compat_ioctl   = compat_ptr_ioctl,
	.release = kvm_tdp_fd_release,
	.mmap = kvm_tdp_fd_mmap,
};

static inline int is_tdp_fd_file(struct file *file)
{
	return file->f_op == &kvm_tdp_fd_fops;
}

static int kvm_tdp_register_importer(struct kvm_tdp_fd *tdp_fd,
				     struct kvm_tdp_importer_ops *ops, void *data)
{
	struct kvm_tdp_importer *importer, *tmp;
	struct kvm_exported_tdp *tdp;

	if (!tdp_fd || !tdp_fd->priv || !ops)
		return -EINVAL;

	tdp = tdp_fd->priv;
	importer = kzalloc(sizeof(*importer), GFP_KERNEL);
	if (!importer)
		return -ENOMEM;

	spin_lock(&tdp->importer_lock);
	list_for_each_entry(tmp, &tdp->importers, node) {
		if (tmp->ops != ops)
			continue;

		kfree(importer);
		spin_unlock(&tdp->importer_lock);
		return -EBUSY;
	}

	importer->ops = ops;
	importer->data = data;
	list_add(&importer->node, &tdp->importers);

	spin_unlock(&tdp->importer_lock);

	return 0;
}

static void kvm_tdp_unregister_importer(struct kvm_tdp_fd *tdp_fd,
					struct kvm_tdp_importer_ops *ops)
{
	struct kvm_tdp_importer *importer, *n;
	struct kvm_exported_tdp *tdp;

	if (!tdp_fd || !tdp_fd->priv)
		return;

	tdp = tdp_fd->priv;
	spin_lock(&tdp->importer_lock);
	list_for_each_entry_safe(importer, n, &tdp->importers, node) {
		if (importer->ops != ops)
			continue;

		list_del(&importer->node);
		kfree(importer);
	}
	spin_unlock(&tdp->importer_lock);
}

static void kvm_tdp_unregister_all_importers(struct kvm_exported_tdp *tdp)
{
	struct kvm_tdp_importer *importer, *n;

	spin_lock(&tdp->importer_lock);
	list_for_each_entry_safe(importer, n, &tdp->importers, node) {
		list_del(&importer->node);
		kfree(importer);
	}
	spin_unlock(&tdp->importer_lock);
}

static void *kvm_tdp_get_metadata(struct kvm_tdp_fd *tdp_fd)
{
	return ERR_PTR(-EOPNOTSUPP);
}

static int kvm_tdp_fault(struct kvm_tdp_fd *tdp_fd, struct mm_struct *mm,
			 unsigned long gfn, struct kvm_tdp_fault_type type)
{
	bool kthread = current->mm == NULL;
	int ret = -EINVAL;

	if (!tdp_fd || !tdp_fd->priv || !tdp_fd->priv->kvm)
		return -EINVAL;

	if (!type.read && !type.write && !type.exec)
		return -EINVAL;

	if (!mm || tdp_fd->priv->kvm->mm != mm)
		return -EINVAL;

	if (!mmget_not_zero(mm))
		return -EPERM;

	if (kthread)
		kthread_use_mm(mm);
	else if (current->mm != mm)
		goto out;

	ret = kvm_arch_fault_exported_tdp(tdp_fd->priv, gfn, type);

	if (kthread)
		kthread_unuse_mm(mm);
out:
	mmput(mm);
	return ret;
}

static const struct kvm_exported_tdp_ops exported_tdp_ops = {
	.register_importer = kvm_tdp_register_importer,
	.unregister_importer = kvm_tdp_unregister_importer,
	.get_metadata = kvm_tdp_get_metadata,
	.fault = kvm_tdp_fault,
};

/**
 * kvm_tdp_fd_get - Public interface to get KVM TDP FD object.
 *
 * @fd:      fd of the KVM TDP FD object.
 * @return:  KVM TDP FD object if @fd corresponds to a valid KVM TDP FD file.
 *           -EBADF if @fd does not correspond a struct file.
 *           -EINVAL if @fd does not correspond to a KVM TDP FD file.
 *
 * Callers of this interface will get a KVM TDP FD object with ref count
 * increased.
 */
struct kvm_tdp_fd *kvm_tdp_fd_get(int fd)
{
	struct file *file;

	file = fget(fd);
	if (!file)
		return ERR_PTR(-EBADF);

	if (!is_tdp_fd_file(file)) {
		fput(file);
		return ERR_PTR(-EINVAL);
	}
	return file->private_data;
}
EXPORT_SYMBOL_GPL(kvm_tdp_fd_get);

/**
 * kvm_tdp_fd_put - Public interface to put ref count of a KVM TDP FD object.
 *
 * @tdp_fd:  KVM TDP FD object.
 *
 * Put reference count of the KVM TDP FD object.
 * After the last reference count of the TDP fd goes away,
 * kvm_tdp_fd_release() will be called to decrease KVM VM ref count and destroy
 * the KVM TDP FD object.
 */
void kvm_tdp_fd_put(struct kvm_tdp_fd *tdp_fd)
{
	if (WARN_ON(!tdp_fd || !tdp_fd->file || !is_tdp_fd_file(tdp_fd->file)))
		return;

	fput(tdp_fd->file);
}
EXPORT_SYMBOL_GPL(kvm_tdp_fd_put);

static void kvm_tdp_fd_flush(struct kvm_exported_tdp *tdp, unsigned long gfn,
			     unsigned long npages)
{
#define INVALID_NPAGES (-1UL)
	bool all = (gfn == 0) && (npages == INVALID_NPAGES);
	struct kvm_tdp_importer *importer;
	unsigned long start, size;

	if (all) {
		start = 0;
		size = -1UL;
	} else {
		start = gfn << PAGE_SHIFT;
		size = npages << PAGE_SHIFT;
	}

	spin_lock(&tdp->importer_lock);

	list_for_each_entry(importer, &tdp->importers, node) {
		if (!importer->ops->invalidate)
			continue;

		importer->ops->invalidate(importer->data, start, size);
	}
	spin_unlock(&tdp->importer_lock);
}

void kvm_tdp_fd_flush_notify(struct kvm *kvm, unsigned long gfn, unsigned long npages)
{
	struct kvm_exported_tdp *tdp;

	spin_lock(&kvm->exported_tdplist_lock);
	list_for_each_entry(tdp, &kvm->exported_tdp_list, list_node)
		kvm_tdp_fd_flush(tdp, gfn, npages);
	spin_unlock(&kvm->exported_tdplist_lock);
}
EXPORT_SYMBOL_GPL(kvm_tdp_fd_flush_notify);
