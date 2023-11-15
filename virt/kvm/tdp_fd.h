/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TDP_FD_H
#define __TDP_FD_H

#ifdef CONFIG_HAVE_KVM_EXPORTED_TDP
int kvm_create_tdp_fd(struct kvm *kvm, struct kvm_create_tdp_fd *ct);

#else
static inline int kvm_create_tdp_fd(struct kvm *kvm, struct kvm_create_tdp_fd *ct)
{
	return -EOPNOTSUPP;
}
#endif /* CONFIG_HAVE_KVM_EXPORTED_TDP */

#endif /* __TDP_FD_H */
