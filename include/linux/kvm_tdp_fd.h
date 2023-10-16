/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __KVM_TDP_FD_H
#define __KVM_TDP_FD_H

#include <linux/types.h>
#include <linux/mm.h>

struct kvm_exported_tdp;
struct kvm_exported_tdp_ops;
struct kvm_tdp_importer_ops;

/**
 * struct kvm_tdp_fd - KVM TDP FD object
 *
 * Interface of exporting KVM TDP page table to external components of KVM.
 *
 * This KVM TDP FD object is created by KVM VM ioctl KVM_CREATE_TDP_FD.
 * On object creation, KVM will find or create a TDP page table, mark it as
 * exported and increase reference count of this exported TDP page table.
 *
 * On object destroy, the exported TDP page table is unmarked as exported with
 * its reference count decreased.
 *
 * During the life cycle of KVM TDP FD object, ref count of KVM VM is hold.
 *
 * Components outside of KVM can get meta data (e.g. page table type, levels,
 * root HPA,...), request page fault on the exported TDP page table and register
 * themselves as importers to receive notification through kvm_exported_tdp_ops
 * @ops.
 *
 * @file:  struct file object associated with the KVM TDP FD object.
 * @ops:   kvm_exported_tdp_ops associated with the exported TDP page table.
 * @priv:  internal data structures used by KVM to manage TDP page table
 *         exported by KVM.
 *
 */
struct kvm_tdp_fd {
	/* Public */
	struct file *file;
	const struct kvm_exported_tdp_ops *ops;

	/* private to KVM */
	struct kvm_exported_tdp *priv;
};

/**
 * kvm_tdp_fd_get - Public interface to get KVM TDP FD object.
 *
 * @fd:       fd of the KVM TDP FD object.
 * @return:   KVM TDP FD object if @fd corresponds to a valid KVM TDP FD file.
 *            -EBADF if @fd does not correspond a struct file.
 *            -EINVAL if @fd does not correspond to a KVM TDP FD file.
 *
 * Callers of this interface will get a KVM TDP FD object with ref count
 * increased.
 */
struct kvm_tdp_fd *kvm_tdp_fd_get(int fd);

/**
 * kvm_tdp_fd_put - Public interface to put ref count of a KVM TDP FD object.
 *
 * @tdp:  KVM TDP FD object.
 *
 * Put reference count of the KVM TDP FD object.
 * After the last reference count of the TDP FD object goes away,
 * kvm_tdp_fd_release() will be called to decrease KVM VM ref count and destroy
 * the KVM TDP FD object.
 */
void kvm_tdp_fd_put(struct kvm_tdp_fd *tdp);

struct kvm_tdp_fault_type {
	u32 read:1;
	u32 write:1;
	u32 exec:1;
};

/**
 * struct kvm_exported_tdp_ops - operations possible on KVM TDP FD object.
 * @register_importer:  This is called from components outside of KVM to register
 *                      importer callback ops and the importer data.
 *                      This callback is a must.
 *                      Returns: 0 on success, negative error code on failure.
 *                              -EBUSY if the importer ops is already registered.
 * @unregister_importer:This is called from components outside of KVM if it does
 *                      not want to receive importer callbacks any more.
 *                      This callback is a must.
 * @fault:              This is called from components outside of KVM to trigger
 *                      page fault on a GPA and to map physical page into the
 *                      TDP page tables exported by KVM.
 *                      This callback is optional.
 *                      If this callback is absent, components outside KVM will
 *                      not be able to trigger page fault and map physical pages
 *                      into the TDP page tables exported by KVM.
 * @get_metadata:       This is called from components outside of KVM to retrieve
 *                      meta data of the TDP page tables exported by KVM, e.g.
 *                      page table type,root HPA, levels, reserved zero bits...
 *                      Returns: pointer to a vendor meta data on success.
 *                               Error PTR on error.
 *                      This callback is a must.
 */
struct kvm_exported_tdp_ops {
	int (*register_importer)(struct kvm_tdp_fd *tdp_fd,
				 struct kvm_tdp_importer_ops *ops,
				 void *importer_data);

	void (*unregister_importer)(struct kvm_tdp_fd *tdp_fd,
				    struct kvm_tdp_importer_ops *ops);

	int (*fault)(struct kvm_tdp_fd *tdp_fd, struct mm_struct *mm,
		     unsigned long gfn, struct kvm_tdp_fault_type type);

	void *(*get_metadata)(struct kvm_tdp_fd *tdp_fd);
};

/**
 * struct kvm_tdp_importer_ops - importer callbacks
 *
 * Components outside of KVM can be registered as importers of KVM's exported
 * TDP page tables via register_importer op in kvm_exported_tdp_ops of a KVM TDP
 * FD object.
 *
 * Each importer must define its own importer callbacks and KVM will notify
 * importers of changes of the exported TDP page tables.
 */
struct kvm_tdp_importer_ops {
	/**
	 * This is called by KVM to notify the importer that a range of KVM
	 * TDP has been invalidated.
	 * When @start is 0 and @size is -1, a whole of KVM TDP is invalidated.
	 *
	 * @data:    the importer private data.
	 * @start:   start GPA of the invalidated range.
	 * @size:    length of in the invalidated range.
	 */
	void (*invalidate)(void *data, unsigned long start, unsigned long size);
};
#endif /* __KVM_TDP_FD_H */
