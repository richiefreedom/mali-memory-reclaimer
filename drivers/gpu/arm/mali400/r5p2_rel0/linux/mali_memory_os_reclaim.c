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

#define pr_fmt(fmt) "[mem_os reclaim] " fmt

/* Linux kernel generic headers. */
#include <linux/dma-mapping.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

/* Graphics Memory Compression (GMC) subsystem's headers. */
#include <linux/gmc_storage.h>
#include <linux/gmc.h>

/* The mali header should be included before others. */
#include "mali_kernel_common.h"

/* Mali internally used headers. */
#include "mali_memory_os_alloc.h"
#include "mali_memory_virtual.h"
#include "mali_kernel_core.h"
#include "mali_kernel_linux.h"
#include "mali_executor.h"
#include "mali_memory.h"
#include "mali_group.h"
#include "mali_osk.h"

/**
 * enum vma_operation - type of semantic operations done on GPU VMAs.
 * @VMA_COMPRESS: compress pages that belong to VMA;
 * @VMA_DECOMPRESS: decompress pages that belong to VMA.
 *
 * Used below to make all the code a bit more generic.
 */
enum vma_operation {
	VMA_COMPRESS = 0,
	VMA_DECOMPRESS,
};

/* The symbols are exported but not mentioned in any header. */
void mali_executor_lock(void);
void mali_executor_unlock(void);

struct gmc_device *mali_mem_os_gmc_device = NULL;

#ifdef DEBUG
static int mali_mem_os_reclaim_debug = 1;
#else
static int mali_mem_os_reclaim_debug = 0;
#endif

/**
 * mali_mem_os_decompress_one_page() - get a page from the compressed storage.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 * @page_node: a pointer to a wrapping descriptor for a page frame.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_decompress_one_page(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend,
		struct mali_page_node *page_node)
{
	gfp_t flags = __GFP_ZERO | __GFP_REPEAT | __GFP_NOWARN | __GFP_COLD;
	struct page *page;
	int err;

	/* Just return if the page is already decompressed. */
	if (mali_page_node_is_decompressed(page_node))
		return 0;

	page = alloc_page(flags);
	if (!page) {
		pr_err("Unable to allocate a page for decompression.\n");
		return -ENOMEM;
	}

	err = gmc_storage_get_page(mali_mem_os_gmc_device->storage, page,
			page_node->handle);
	if (err) {
		__free_page(page);
		return -EINVAL;
	}

	/* Page locking is non necessary here. */
	ClearPagePrivate(page);
	page_node->page = page;
	mali_page_node_set_decompressed(page_node);

	mali_mem_os_allocator_inc_allocated_pages();

	return 0;
}

/**
 * mali_mem_os_find_faulted_entry() - find a page node corresponding to the
 * address in the allocation.
 *
 * Works both for CPU and GPU page faults, a variable 'cpu' controls the
 * behavior.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to backend descriptor.
 * @address: a faulted address (virtual GPU or CPU one).
 * @cpu: a flag controlling the behavior. 1 - CPU, 0 - GPU page fault.
 *
 * Returns a valid pointer to struct mali_page_node on success, NULL otherwise.
 */
static struct mali_page_node *mali_mem_os_find_faulted_entry(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend,
		void *address, bool cpu)
{
	unsigned long address_offset;
	unsigned long faulted_page_num;
	unsigned long cur_page_num = 0;

	struct mali_page_node *page_node;
	struct mali_page_node *selected_entry = NULL;

	/* Compute an offset from start of the area. */
	if (cpu)
		address_offset = address - (void *)allocation->cpu_mapping.addr;
	else
		address_offset = address - (void *)allocation->mali_mapping.addr;

	/* Convert the offset to faulted page number. */
	faulted_page_num = address_offset / PAGE_SIZE;

	/* Get the corresponding mem_entry for O(n). */
	list_for_each_entry(page_node, &backend->os_mem.pages, list) {
		if (faulted_page_num == cur_page_num) {
			selected_entry = page_node;
			break;
		}
		cur_page_num++;
	}

	if (!selected_entry)
		pr_err("Unable to find corresponding mem_entry.\n");

	return selected_entry;
}

/**
 * mali_mem_os_set_cpu_faulted_page() - set necessary CPU mapping for a faulted
 * page.
 *
 * @vmf: a pointer to a vm_fault control structure.
 * @vma: a pointer to a virtual memory area descriptor.
 * @page_node: a pointer to a descriptor wrapping a page frame.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_set_cpu_faulted_page(
		struct vm_fault *vmf,
		struct vm_area_struct *vma,
		struct mali_page_node *page_node)
{
	int ret = 0;

	ret = vm_insert_pfn(vma, (unsigned long)vmf->virtual_address,
				page_to_pfn(page_node->page));
	if (ret && -EBUSY != ret) {
		pr_err("Unable to map to CPU, ret = %d, address = 0x%lx\n",
				ret, (unsigned long)vmf->virtual_address);
	} else {
		ret = 0;
	}

#ifdef DEBUG
	if (!ret) {
		MALI_DEBUG_PRINT(3, ("mapping the page back:\n"));
		MALI_DEBUG_PRINT(3, ("\taddress = %p\n", vmf->virtual_address));
		MALI_DEBUG_PRINT(3, ("\tpage = %p\n", page_node->page));
	}
#endif
	return ret;
}

/**
 * mali_mem_os_cpu_page_fault() - handle a page fault for MALI_MEM_OS
 * allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 * @vmf: a pointer to a vm_fault control structure.
 * @vma: a pointer to a virtual memory area descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
int mali_mem_os_cpu_page_fault(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend,
		struct vm_fault *vmf,
		struct vm_area_struct *vma)
{
	void __user *address = vmf->virtual_address;
	struct mali_page_node *page_node;
	int ret = 0;

	MALI_DEBUG_ASSERT_POINTER(allocation);
	MALI_DEBUG_ASSERT(MALI_MEM_ALLOCATION_VALID_MAGIC == allocation->magic);
	MALI_DEBUG_ASSERT(backend->type == MALI_MEM_OS);

	_mali_osk_mutex_wait(allocation->session->memory_lock);
	mutex_lock(&allocation->mutex);
	mutex_lock(&backend->mutex);

	page_node = mali_mem_os_find_faulted_entry(allocation, backend,
			address, true);
	if (!page_node) {
		pr_err("Page node is not found on page fault.\n");
		ret = -ENOENT;
		goto out;
	}

	ret = mali_mem_os_decompress_one_page(allocation, backend, page_node);
	if (ret) {
		pr_err("Error during decompression: %d.\n", ret);
		goto out;
	}

	flush_dcache_page(page_node->page);

	/* Mapping the page to VMA is done here. */
	ret = mali_mem_os_set_cpu_faulted_page(vmf, vma, page_node);
out:
	mutex_unlock(&backend->mutex);
	mutex_unlock(&allocation->mutex);
	_mali_osk_mutex_signal(allocation->session->memory_lock);
	return ret;
}

/**
 * mali_mem_os_invalidate_pages() - invalidate compressed data in the storage
 * allociated with a specified allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 *
 * Returns number of invalidated pages.
 */
u32 mali_mem_os_invalidate_pages(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	struct mali_page_node *page_node, *temp;
	u32 num_invalidated = 0;

	list_for_each_entry_safe(page_node, temp, &backend->os_mem.pages, list) {
		if (mali_page_node_is_mapped(page_node))
			continue;

		list_del(&page_node->list);

		/*
		 * If the page is compressed, its data is stored somewhere in
		 * the GMC storage, we have to invalidate the data.
		 */
		if (mali_page_node_is_compressed(page_node))
			gmc_storage_invalidate_page(
					mali_mem_os_gmc_device->storage,
					page_node->handle);
		/*
		 * If the page is already allocated, that means "decompressed"
		 * but not "mapped", we have to free the page too.
		 */
		if (page_node->page)
			mali_mem_os_put_page_no_unmap(page_node->page);

		kfree(page_node);

		/*
		 * Do not forget to update the backend statistics. This is
		 * necessary for correct freeing of the backend in the next
		 * call.
		 */
		backend->os_mem.count--;
		num_invalidated++;
	}

	return num_invalidated;
}

/**
 * mali_mem_os_map_gpu_entry() - map a page frame to a virtual address.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @virt: a GPU virtual address.
 * @page_node: a pointer to a page_node descriptor wrapping a page frame.
 *
 */
static void mali_mem_os_map_gpu_entry(mali_mem_allocation *allocation, u32 virt,
		mali_page_node *page_node)
{
	struct mali_page_directory *pagedir;
	dma_addr_t dma_addr;
	u32 phys;

	pagedir = mali_session_get_page_directory(allocation->session);

	MALI_DEBUG_ASSERT(!mali_page_node_is_compressed(page_node));

	if (mali_page_node_is_mapped(page_node))
		return;

	dma_addr = dma_map_page(&mali_platform_device->dev, page_node->page, 0,
			_MALI_OSK_MALI_PAGE_SIZE, DMA_TO_DEVICE);

	SetPagePrivate(page_node->page);
	set_page_private(page_node->page, dma_addr);

	phys = page_private(page_node->page);

	/* Align the address. */
	virt = virt & ~(PAGE_SIZE - 1);

	mali_mmu_pagedir_update(pagedir, virt, phys, MALI_MMU_PAGE_SIZE,
			MALI_MMU_FLAGS_DEFAULT);

	mali_page_node_set_mapped(page_node);
}

/**
 * mali_mem_os_address_in_allocation() - check if address is in bounds of an
 * allocation.
 *
 * @address: a GPU virtual address.
 * @allocation: a pointer to an allocation descriptor.
 *
 * Returns true if the address belongs to the allocation, false otherwise.
 */
static bool mali_mem_os_address_in_allocation(u32 address,
		struct mali_mem_allocation *allocation)
{
	u32 start = allocation->mali_mapping.addr;
	u32 end = start + allocation->vsize;

	if (address >= start && address < end)
		return true;

	return false;
}

void mali_l2_cache_invalidate_all(void);

/**
 * mali_mem_os_restore_allocation() - restore a page frame laying behind a
 * specified address in specific allocation backed by a specific allocation
 * backend.
 *
 * @group: a pointer to a group descriptor.
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 * @address: a GPU virtual address.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_restore_allocation(
		struct mali_group *group,
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend,
		u32 address)
{
	struct mali_page_node *page_node;
	struct mali_page_directory *pagedir;

	MALI_DEBUG_ASSERT_LOCK_HELD(allocation->session->memory_lock);

	MALI_DEBUG_ASSERT(backend->type == MALI_MEM_OS);
	MALI_DEBUG_ASSERT(address &&
			mali_mem_os_address_in_allocation(address, allocation));

	pagedir = mali_session_get_page_directory(allocation->session);

	MALI_DEBUG_ASSERT_POINTER(pagedir);

	mutex_lock(&allocation->mutex);
	mutex_lock(&backend->mutex);

	page_node = mali_mem_os_find_faulted_entry(allocation, backend,
			(void *)address, false);
	if (!page_node) {
		mutex_unlock(&backend->mutex);
		mutex_unlock(&allocation->mutex);
		return -EINVAL;
	}

	if (mali_mem_os_decompress_one_page(allocation, backend, page_node)) {
		mutex_unlock(&backend->mutex);
		mutex_unlock(&allocation->mutex);
		return -EINVAL;
	}

	mali_executor_lock();

	WARN_ON(allocation->session != group->session);

	if (!mali_mmu_in_page_fault(group->mmu, false)) {
		/*
		 * During lock-free period above someone handled
		 * the page fault for us.
		 */
		MALI_DEBUG_PRINT(3, ("[%d][%x] Page fault already handled\n",
				raw_smp_processor_id(), address));
		pr_warn("The page fault is already handled!\n");
		goto out;
	}

	mali_mem_os_map_gpu_entry(allocation, address, page_node);
	_mali_osk_write_mem_barrier();
	mali_l2_cache_invalidate_all();

	/*
	 * Modify the timer to prevent early timeouts (because we
	 * will release lock, multiple page faults may happen
	 * and this job could be scheduled multiple time).
	 */
	_mali_osk_timer_mod(group->timeout_timer,
				_mali_osk_time_mstoticks(mali_max_job_runtime));

	/*
	 * The stall here is not necessary, because being in the page fault mode
	 * guarantees that page table entries won't be read by MMU and
	 * everything will be accessed in a consistent state.
	 */
	mali_mmu_zap_tlb_without_stall(group->mmu);

	MALI_DEBUG_PRINT(3,
	("[%d][%x] Page fault handled, session %p, unmasking interrupts\n",
		raw_smp_processor_id(), address, group->session));

	/* Clear the page fault interrupt */
	mali_hw_core_register_write(&group->mmu->hw_core,
			MALI_MMU_REGISTER_INT_CLEAR,
			MALI_MMU_INTERRUPT_PAGE_FAULT);

	mali_mmu_page_fault_done(group->mmu);
	mali_mmu_unmask_all_interrupts(group->mmu);

	MALI_DEBUG_PRINT(3,
		("[%d][%x] Page fault handled fully, unmasked interrupts\n",
		raw_smp_processor_id(), address));
out:
	mali_executor_unlock();
	mutex_unlock(&backend->mutex);
	mutex_unlock(&allocation->mutex);

	return 0;
}

/**
 * mali_mem_os_restore_vma() - restore a page frame laying behind a specified
 * address in a specific VMA.
 *
 * @group: a pointer to a group descriptor.
 * @vma_node: a pointer to a GPU VMA descriptor.
 * @address: a GPU virtual address.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_restore_vma(struct mali_group *group,
		struct mali_vma_node *vma_node, u32 address)
{
	struct mali_mem_allocation *allocation;
	struct mali_mem_backend *backend;
	int ret = 0;

	allocation = container_of(vma_node, struct mali_mem_allocation,
			mali_vma_node);

	MALI_DEBUG_ASSERT(allocation->magic == MALI_MEM_ALLOCATION_VALID_MAGIC);

	mutex_lock(&mali_idr_mutex);

	backend = idr_find(&mali_backend_idr, allocation->backend_handle);
	if (!backend) {
		pr_warn("Backend is not found.\n");
		ret = -ENOENT;
		goto out;
	}

	ret = mali_mem_os_restore_allocation(group, allocation,
			backend, address);
out:
	mutex_unlock(&mali_idr_mutex);
	return ret;
}

/**
 * mali_mem_os_check_vma() - check that a specified VMA node contains an address
 * inside.
 *
 * @vma_node: a pointer to a GPU VMA descriptor.
 * @address: a GPU virtual address.
 *
 * Returns 0 in the case of address match, -ENOENT otherwise.
 */
static int mali_mem_os_check_vma(struct mali_vma_node *vma_node, u32 address)
{
	struct mali_mem_allocation *allocation;

	allocation = container_of(vma_node, struct mali_mem_allocation,
			mali_vma_node);

	MALI_DEBUG_ASSERT(allocation->magic == MALI_MEM_ALLOCATION_VALID_MAGIC);
	MALI_DEBUG_ASSERT_LOCK_HELD(allocation->session->memory_lock);

	if (allocation->type != MALI_MEM_OS)
		return -ENOENT;

	if (address && !mali_mem_os_address_in_allocation(address, allocation))
		return -ENOENT;

	return 0;
}

/**
 * mali_mem_os_check_session() - try to find a session in the sessions list and
 * get a reference to the session if it is found.
 *
 * @session: a pointer to a session descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_check_session(struct mali_session_data *session)
{
	struct mali_session_data *cur, *tmp;
	int res = -ENOENT;

	MALI_SESSION_FOREACH(cur, tmp, link) {
		if (cur == session) {
			res = 0;
			break;
		}
	}

	return res;
}

/**
 * mali_mem_os_restore_session() - try to restore a page by specified address in
 * a session.
 *
 * @group: a pointer to a group descriptor.
 * @session: a pointer to a session descriptor.
 * @address: a 32-bit GPU virtual address of the page frame.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
int mali_mem_os_restore_session(struct mali_group *group,
		struct mali_session_data *session,
		u32 address)
{
	struct mali_vma_node *vma_node;
	int err = 0;

	MALI_DEBUG_ASSERT(session);

	mali_session_lock(_MALI_OSK_LOCKMODE_RO);
	if (mali_mem_os_check_session(session)) {
		pr_warn("Unable to find a faulted session.\n");
		err = -ENOENT;
		goto out_unlock_session;
	}

	mali_session_memory_lock(session);
	down_read(&session->allocation_mgr.vm_lock);

	/*
	 * We use a version of the function that doesn't do any locking
	 * internally. Instead of this we do VM locking outside of the function
	 * and keep the lock all the time the page fault on the session is
	 * handled.
	 */
	vma_node = _mali_vma_offset_search(&session->allocation_mgr,
			address, 0);

	if (!vma_node) {
		pr_warn("Unable to find a faulted VMA node.\n");
		err = -ENOENT;
		goto out_unlock_vm_and_mem;
	}

	if (mali_mem_os_check_vma(vma_node, address)) {
		pr_warn("Faulted VMA node is not suitable.\n");
		err = -ENOENT;
		goto out_unlock_vm_and_mem;
	}

	err = mali_mem_os_restore_vma(group, vma_node, address);

out_unlock_vm_and_mem:
	up_read(&session->allocation_mgr.vm_lock);
	mali_session_memory_unlock(session);
out_unlock_session:
	mali_session_unlock(_MALI_OSK_LOCKMODE_RO);
	return err;
}

/**
 * mali_mem_os_compress() - compress the page.
 *
 * @page_node: a pointer to a page_node corresponding to some page frame in the
 * allocation.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_compress(struct mali_page_node *page_node)
{
	struct gmc_storage_handle *handle;

	handle = gmc_storage_put_page(mali_mem_os_gmc_device->storage,
			page_node->page);
	if (!IS_ERR(handle)) {
		page_node->handle = handle;
		mali_page_node_set_compressed(page_node);

		return 0;
	}

	switch (PTR_ERR(handle)) {
	/*
	 * Badly-compressed pages don't need any special actions. Such pages are
	 * considered as just unmapped.
	 */
	case -EFBIG:
		return 0;
	default:
		return PTR_ERR(handle);
	}
}

/**
 * mali_mem_os_unmap_dma_and_compress() - unmap from DMA point of view and
 * compress all the pages corresponding to a specified allocation backed by a
 * corresponding backend.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_unmap_dma_and_compress(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	struct mali_page_node *page_node;

	list_for_each_entry(page_node, &backend->os_mem.pages, list) {
		if (mali_page_node_is_unmapped(page_node))
			continue;

		MALI_DEBUG_ASSERT(PagePrivate(page_node->page));

		dma_unmap_page(&mali_platform_device->dev,
				page_private(page_node->page),
				_MALI_OSK_MALI_PAGE_SIZE, DMA_FROM_DEVICE);

		ClearPagePrivate(page_node->page);
		mali_page_node_set_unmapped(page_node);

		MALI_DEBUG_ASSERT(!mali_page_node_is_compressed(page_node));

		/* Compress the entry corresponding to a single page. */
		if (mali_mem_os_compress(page_node))
			return -EINVAL;

		if (mali_page_node_is_compressed(page_node)) {
			mali_mem_os_allocator_dec_allocated_pages();
			put_page(page_node->page);
			page_node->page = NULL;
		}
	}

	return 0;
}

/**
 * mali_mem_os_unmap_cpu() - get rid of CPU mappings of a specified allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_unmap_cpu(struct mali_mem_allocation *allocation)
{
	int ret;

	/* Allocations mapped to more than one VMA should not be reclaimed. */
	MALI_DEBUG_ASSERT(_mali_osk_atomic_read(&allocation->mem_alloc_refcount)
			== 2);

	ret = zap_vma_ptes(allocation->cpu_mapping.vma,
			(unsigned long)allocation->cpu_mapping.addr,
			allocation->vsize);
	if (ret) {
		pr_err("Error. Unable to zap VMA: 0x%p\n",
				allocation->cpu_mapping.vma);
		return -EINVAL;
	}

	return 0;
}

/**
 * mali_mem_os_unmap_gpu() - get rid of GPU mappings on a specified allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 */
static void mali_mem_os_unmap_gpu(struct mali_mem_allocation *allocation)
{
	mali_mmu_pagedir_unmap_for_pagefault(
			allocation->session->page_directory,
			allocation->mali_mapping.addr,
			allocation->vsize);
}

/**
 * mali_mem_os_reclaim_allocation() - reclaim (compress) the pages that belong
 * to the allocation with specific backend (a chunk of physical memory allocated
 * for internal needs.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_reclaim_allocation(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	int err = 0;

	MALI_DEBUG_ASSERT_LOCK_HELD(allocation->session->memory_lock);

	mutex_lock(&allocation->mutex);
	mutex_lock(&backend->mutex);

	if (backend->type != MALI_MEM_OS)
		goto out_unlock;

	MALI_DEBUG_ASSERT(!(MALI_MEM_BACKEND_FLAG_COWED & backend->cow_flag));
	MALI_DEBUG_ASSERT(allocation->vsize == allocation->psize);
	/* Check why this invariant can be failed. */
	WARN_ON(allocation->vsize != backend->os_mem.count * PAGE_SIZE);

	if (2 != _mali_osk_atomic_read(&allocation->mem_alloc_refcount)) {
		MALI_DEBUG_PRINT(3, ("Reference counter != 2.\n"));
		goto out_unlock;
	}

	if (mali_mem_os_unmap_cpu(allocation)) {
		pr_warn("Unable to unmap from CPU.\n");
		err = -EINVAL;
		goto out_unlock;
	}

	mali_executor_lock();
	mali_mem_os_unmap_gpu(allocation);
	mali_executor_unlock();

	mali_executor_zap_all_active(allocation->session);

	/*
	 * There is nothing to do with error handling here. Just report about
	 * the problem to the log, because the failed page is just unmapped and
	 * can be mapped on demand.
	 */
	WARN_ON(mali_mem_os_unmap_dma_and_compress(allocation, backend));

out_unlock:
	mutex_unlock(&backend->mutex);
	mutex_unlock(&allocation->mutex);
	return err;
}

/**
 * mali_mem_os_decompress_pages() - decompress pages that belongs
 * to the allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_decompress_pages(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	struct mali_page_node *page_node;

	list_for_each_entry(page_node, &backend->os_mem.pages, list) {
		if (mali_page_node_is_decompressed(page_node))
			continue;

		MALI_DEBUG_ASSERT(mali_page_node_is_compressed(page_node));
		if (mali_mem_os_decompress_one_page(allocation,
					backend, page_node))
			return -EINVAL;
	}

	return 0;
}

/**
 * mali_mem_os_decompress_allocation() - decompress the memory that belongs
 * to the allocation.
 *
 * @allocation: a pointer to an allocation descriptor.
 * @backend: a pointer to a backend descriptor.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_decompress_allocation(
		struct mali_mem_allocation *allocation,
		struct mali_mem_backend *backend)
{
	int err = 0;

	MALI_DEBUG_ASSERT_LOCK_HELD(allocation->session->memory_lock);

	mutex_lock(&allocation->mutex);
	mutex_lock(&backend->mutex);

	if (backend->type != MALI_MEM_OS)
		goto out_unlock;

	MALI_DEBUG_ASSERT(!(MALI_MEM_BACKEND_FLAG_COWED & backend->cow_flag));

	err = mali_mem_os_decompress_pages(allocation, backend);

out_unlock:
	mutex_unlock(&backend->mutex);
	mutex_unlock(&allocation->mutex);
	return err;
}

typedef int (*mali_mem_os_vma_operation)
	(struct mali_mem_allocation *, struct mali_mem_backend *);

static mali_mem_os_vma_operation mali_mem_os_vma_operations[] = {
	[VMA_COMPRESS] = mali_mem_os_reclaim_allocation,
	[VMA_DECOMPRESS] = mali_mem_os_decompress_allocation,
};

/**
 * mali_mem_os_vma_op() - perform a reclaimer operation on a virtual memory
 * area.
 *
 * @vma_node: a pointer to a virtual memory area descriptor (mali).
 * @data: a type of VMA operation the function must do.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_vma_op(struct mali_vma_node *vma_node, void *data)
{
	enum vma_operation op = (enum vma_operation) data;
	struct mali_mem_allocation *allocation;
	struct mali_mem_backend *backend;
	int ret = 0;

	allocation = container_of(vma_node, struct mali_mem_allocation,
			mali_vma_node);

	MALI_DEBUG_ASSERT(allocation->magic == MALI_MEM_ALLOCATION_VALID_MAGIC);

	mutex_lock(&mali_idr_mutex);

	backend = idr_find(&mali_backend_idr, allocation->backend_handle);
	if (!backend) {
		ret = -ENOENT;
		goto out;
	}

	ret = mali_mem_os_vma_operations[op](allocation, backend);
out:
	mutex_unlock(&mali_idr_mutex);
	return ret;
}

/**
 * mali_mem_os_reclaim_obtain_task() - obtain a pointer to corresponding task
 * struct.
 *
 * Performs careful lookup of a task_struct by tgid under rcu_read_lock.
 *
 * Returns a valid pointer to task_struct on success, NULL otherwise.
 */
static struct task_struct *mali_mem_os_reclaim_obtain_task(pid_t pid)
{
	struct task_struct *task;

	rcu_read_lock();
	task = find_task_by_vpid(pid);
	if (task)
		get_task_struct(task);
	rcu_read_unlock();

	return task;
}

/**
 * mali_mem_os_reclaim_lock_task() - do all complex task-related locking.
 *
 * @task: a pointer to some t to be locked.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_reclaim_lock_task(struct task_struct *task)
{
	struct mm_struct *mm = NULL;

	task_lock(task);
	if (task->mm) {
		mm = task->mm;
		atomic_inc(&mm->mm_count);
	}
	task_unlock(task);

	if (!mm) {
		put_task_struct(task);
		return -ENOENT;
	}

	down_write(&mm->mmap_sem);

	return 0;
}

/**
 * mali_mem_os_reclaim_unlock_task() - drop all task-related locks.
 *
 * @task: a pointer to some task_struct previously locked with
 * mali_mem_os_reclaim_lock_task().
 */
static void mali_mem_os_reclaim_unlock_task(struct task_struct *task)
{
	up_write(&task->mm->mmap_sem);
	mmdrop(task->mm);
}

/**
 * mali_mem_os_reclaim_release_task() - put a reference to a specified task
 * struct.
 *
 * @task: a pointer to some task_struct previously referenced with
 * mali_mem_os_reclaim_obtain_task().
 */
static void mali_mem_os_reclaim_release_task(struct task_struct *task)
{
	put_task_struct(task);
}

/**
 * mali_mem_os_walk_session() - reclaim (compress) regions corresponding to
 * the specified session.
 *
 * @session: a pointer to some session descriptor.
 * @op: operation to be done on graphical memory of a process.
 *
 * Returns 0 if on success, -<error code> otherwise.
 */
static int mali_mem_os_walk_session(struct mali_session_data *session,
		enum vma_operation op)
{
	struct task_struct *task;
	int err = 0;

	task = mali_mem_os_reclaim_obtain_task(session->pid);
	if (!task)
		return -ENOENT;
	/*
	 * There is no need to put the task struct got by the previous call in
	 * the case of error. The following function does it itself.
	 */
	if (mali_mem_os_reclaim_lock_task(task))
		return -ENOENT;

	mali_session_memory_lock(session);
	err = mali_vma_for_each_data(
			&session->allocation_mgr,
			mali_mem_os_vma_op,
			(void *)op
			);
	mali_session_memory_unlock(session);

	mali_mem_os_reclaim_unlock_task(task);
	mali_mem_os_reclaim_release_task(task);

	return err;
}

/**
 * mali_mem_os_walk_all() - reclaim (compress) all the graphical memory
 * available in the system.
 *
 * @op: operation to be done on graphical memory of a process.
 *
 * Returns 0 if success, -<error code> otherwise.
 */
static int mali_mem_os_walk_all(enum vma_operation op)
{
	struct mali_session_data *session, *tmp;
	int ret = 0, num_err = 0;

	mali_session_lock(_MALI_OSK_LOCKMODE_RO);

	MALI_SESSION_FOREACH(session, tmp, link) {
		ret = mali_mem_os_walk_session(session, op);
		if (ret) {
			pr_warn("Error during walk the sessions list: %d.\n",
					ret);
			num_err++;
		}
	}

	mali_session_unlock(_MALI_OSK_LOCKMODE_RO);

	if (num_err)
		ret = -EINVAL;

	return ret;
}

/**
 * mali_mem_os_find_session() - find a session corresponding to tgid.
 *
 * @tgid: a process ID the session is assigned to.
 *
 * Returns a pointer to mali_session_data structure or NULL.
 */
static struct mali_session_data *mali_mem_os_find_session(pid_t tgid)
{
	struct mali_session_data *session, *tmp, *found_session = NULL;

	MALI_SESSION_FOREACH(session, tmp, link) {
		if (session->pid == tgid) {
			found_session = session;
			break;
		}
	}

	return found_session;
}

/**
 * mali_mem_os_walk_process() - perform an operation (COMPRESS || DECOMPRESS)
 * for graphical memory related to a specific process.
 *
 * @tgid: PID of a process;
 * @op: operation to be done on graphical memory of a process.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
static int mali_mem_os_walk_process(pid_t tgid, enum vma_operation op)
{
	struct mali_session_data *found_session = NULL;
	int ret = -ENOENT;

	/*
	 * By convention the GMC infrastructure expects some reaction on a
	 * special case, tgid == 0. This means that the user wants to perform
	 * and operation for all the graphical memory available in the system.
	 */
	if (0 == tgid)
		return mali_mem_os_walk_all(op);

	/* Locks a list of sessions in spite of its name. */
	mali_session_lock(_MALI_OSK_LOCKMODE_RO);

	found_session = mali_mem_os_find_session(tgid);
	if (!found_session) {
		pr_warn("Session is not found.\n");
		goto out;
	}

	ret = mali_mem_os_walk_session(found_session, op);
out:
	mali_session_unlock(_MALI_OSK_LOCKMODE_RO);
	return ret;
}

/* GMC callback: compress memory associated with specific process. */
static int mali_mem_os_reclaim_process(pid_t tgid, struct gmc_device *gmc)
{
	return mali_mem_os_walk_process(tgid, VMA_COMPRESS);
}

/* GMC callback: decompress memory associated with specific process. */
static int mali_mem_os_restore_process(pid_t tgid, struct gmc_device *gmc)
{
	if (!mali_mem_os_reclaim_debug)
		return -EPERM;

	return mali_mem_os_walk_process(tgid, VMA_DECOMPRESS);
}

/* Operations conventionally provided to GMC framework. */
static struct gmc_ops mali_mem_os_gmc_ops = {
	.compress_kctx   = mali_mem_os_reclaim_process,
	.decompress_kctx = mali_mem_os_restore_process,
};

/**
 * mali_mem_os_reclaimer_init() - prepare the reclaimer for work.
 *
 * Returns 0 on success, -<error code> otherwise.
 */
int mali_mem_os_reclaimer_init(void)
{
	mali_mem_os_gmc_device = kmalloc(sizeof(*mali_mem_os_gmc_device),
			GFP_KERNEL);
	if (!mali_mem_os_gmc_device)
		return -ENOMEM;

	if (gmc_register_device(&mali_mem_os_gmc_ops, mali_mem_os_gmc_device)) {
		kfree(mali_mem_os_gmc_device);
		mali_mem_os_gmc_device = NULL;

		return -EINVAL;
	}

	return 0;
}
