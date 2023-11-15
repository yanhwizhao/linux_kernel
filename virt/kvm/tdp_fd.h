/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __TDP_FD_H
#define __TDP_FD_H

static inline int kvm_create_tdp_fd(struct kvm *kvm, struct kvm_create_tdp_fd *ct)
{
	return -EOPNOTSUPP;
}

#endif /* __TDP_FD_H */
