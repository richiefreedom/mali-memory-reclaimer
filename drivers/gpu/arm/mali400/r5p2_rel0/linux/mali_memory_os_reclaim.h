/*
 * Copyright 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Authors:
 *   Sergei Rogachev <s.rogachev@samsung.com>
 *
 * This file is part of MALI Utgard Reclaimer for MALI_MEM_OS
 * allocations also known as "Utgard GMC" (graphical memory compression).
 *
 * "Utgard GMC" is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * "Utgard GMC" is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with "Utgard GMC".  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __MALI_MEMORY_OS_RECLAIM_H__
#define __MALI_MEMORY_OS_RECLAIM_H__

#include "mali_kernel_common.h"
#include "mali_group.h"

extern struct gmc_device *mali_mem_os_gmc_device;

#ifdef CONFIG_MALI_MEM_OS_RECLAIM
int mali_mem_os_reclaimer_init(void);
int mali_mem_os_restore_session(struct mali_group *group,
		struct mali_session_data *session, u32 address);
u32 mali_mem_os_invalidate_pages(struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend);
int mali_mem_os_cpu_page_fault(struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend, struct vm_fault *vmf,
		struct vm_area_struct *vma);
#else
static inline int
mali_mem_os_reclaimer_init(void)
{
	return 0;
}

static inline int
mali_mem_os_restore_session(struct mali_group *group,
		struct mali_session_data *session, u32 address)
{
	return -EINVAL;
}

static inline
u32 mali_mem_os_invalidate_pages(struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	return 0;
}

static inline
int mali_mem_os_cpu_page_fault(struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend, struct vm_fault *vmf,
		struct vm_area_struct *vma)
{
	MALI_DEBUG_ASSERT(0);
	return VM_FAULT_SIGBUS;
}
#endif

#endif /* __MALI_MEMORY_OS_RECLAIM_H__ */
