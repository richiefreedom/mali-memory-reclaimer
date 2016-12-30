/*
 * Copyright (C) 2013-2015 ARM Limited. All rights reserved.
 * 
 * This program is free software and is provided to you under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation, and any use by you of this program is subject to the terms of such GNU licence.
 * 
 * A copy of the licence is included with the program, and can also be obtained from Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __MALI_MEMORY_TYPES_H__
#define __MALI_MEMORY_TYPES_H__

#if defined(CONFIG_MALI400_UMP)
#include "ump_kernel_interface.h"
#endif

typedef u32 mali_address_t;

typedef enum mali_mem_type {
	MALI_MEM_OS,
	MALI_MEM_EXTERNAL,
	MALI_MEM_DMA_BUF,
	MALI_MEM_UMP,
	MALI_MEM_BLOCK,
	MALI_MEM_COW,
	MALI_MEM_TYPE_MAX,
} mali_mem_type;

typedef struct mali_block_item {
	/* for block type, the block_phy is alway page size align
	* so use low 12bit used for ref_cout.
	*/
	unsigned long phy_addr;
} mali_block_item;


typedef enum mali_page_node_type {
	MALI_PAGE_NODE_OS,
	MALI_PAGE_NODE_BLOCK,
#ifdef CONFIG_MALI_MEM_OS_RECLAIM
	MALI_PAGE_NODE_OS_UNMAPPED,
	MALI_PAGE_NODE_OS_COMPRESSED,
#endif
} mali_page_node_type;

typedef struct mali_page_node {
	struct list_head list;
	union {
		struct page *page;
		mali_block_item *blk_it; /*pointer to block item*/
	};
	struct gmc_storage_handle *handle;
	u32 type;
} mali_page_node;

#ifdef CONFIG_MALI_MEM_OS_RECLAIM

#define mali_page_node_is_compressed(node) \
	((node)->type == MALI_PAGE_NODE_OS_COMPRESSED)

#define mali_page_node_is_decompressed(node) \
	(!(mali_page_node_is_compressed((node))))

#define mali_page_node_is_unmapped(node)               \
	((node)->type == MALI_PAGE_NODE_OS_UNMAPPED || \
	 (node)->type == MALI_PAGE_NODE_OS_COMPRESSED)

#define mali_page_node_is_mapped(node) \
	((node)->type == MALI_PAGE_NODE_OS)

#define mali_page_node_set_compressed(node) \
	(node)->type = MALI_PAGE_NODE_OS_COMPRESSED

#define mali_page_node_set_unmapped(node) \
	(node)->type = MALI_PAGE_NODE_OS_UNMAPPED

#define mali_page_node_set_decompressed(node) \
	mali_page_node_set_unmapped((node))

#define mali_page_node_set_mapped(node) \
	(node)->type = MALI_PAGE_NODE_OS

#endif /* CONFIG_MALI_MEM_OS_RECLAIM */

typedef struct mali_mem_os_mem {
	struct list_head pages;
	u32 count;
} mali_mem_os_mem;

typedef struct mali_mem_dma_buf {
#if defined(CONFIG_DMA_SHARED_BUFFER)
	struct mali_dma_buf_attachment *attachment;
#endif
} mali_mem_dma_buf;

typedef struct mali_mem_external {
	dma_addr_t phys;
	u32 size;
} mali_mem_external;

typedef struct mali_mem_ump {
#if defined(CONFIG_MALI400_UMP)
	ump_dd_handle handle;
#endif
} mali_mem_ump;

typedef struct block_allocator_allocation {
	/* The list will be released in reverse order */
	struct block_info *last_allocated;
	u32 mapping_length;
	struct block_allocator *info;
} block_allocator_allocation;

typedef struct mali_mem_block_mem {
	struct list_head pfns;
	u32 count;
} mali_mem_block_mem;

typedef struct mali_mem_virt_mali_mapping {
	mali_address_t addr; /* Virtual Mali address */
	u32 properties;      /* MMU Permissions + cache, must match MMU HW */
} mali_mem_virt_mali_mapping;

typedef struct mali_mem_virt_cpu_mapping {
	void __user *addr;
	struct vm_area_struct *vma;
} mali_mem_virt_cpu_mapping;

#define MALI_MEM_ALLOCATION_VALID_MAGIC 0xdeda110c
#define MALI_MEM_ALLOCATION_FREED_MAGIC 0x10101010

typedef struct mali_mm_node {
	/* MALI GPU vaddr start, use u32 for mmu only support 32bit address*/
	uint32_t start; /* GPU vaddr */
	uint32_t size;  /* GPU allocation virtual size */
	unsigned allocated : 1;
} mali_mm_node;

typedef struct mali_vma_node {
	struct mali_mm_node vm_node;
	struct rb_node vm_rb;
} mali_vma_node;


typedef struct mali_mem_allocation {
	MALI_DEBUG_CODE(u32 magic);
	mali_mem_type type;                /**< Type of memory */
	u32 flags;                         /**< Flags for this allocation */

	struct mali_session_data *session; /**< Pointer to session that owns the allocation */

	mali_mem_virt_cpu_mapping cpu_mapping; /**< CPU mapping */
	mali_mem_virt_mali_mapping mali_mapping; /**< Mali mapping */

	/* add for new memory system */
	struct mali_vma_node mali_vma_node;
	u32 vsize; /* virtual size*/
	u32 psize; /* physical backend memory size*/
	struct list_head list;
	s32 backend_handle; /* idr for mem_backend */
	_mali_osk_atomic_t mem_alloc_refcount;
	struct mutex mutex;
} mali_mem_allocation;

/* COW backend memory type */
typedef struct mali_mem_cow {
	struct list_head pages;  /**< all pages for this cow backend allocation,
                                                                including new allocated pages for modified range*/
	u32 count;               /**< number of pages */
	s32 change_pages_nr;
} mali_mem_cow;

#define MALI_MEM_BACKEND_FLAG_COWED                   0x1/* COW has happen on this backend */
#define MALI_MEM_BACKEND_FLAG_COW_CPU_NO_WRITE        0x2/* this is an COW backend, mapped as not allowed cpu to write */

typedef struct mali_mem_backend {
	mali_mem_type type;                /**< Type of backend memory */
	u32 flags;                         /**< Flags for this allocation */
	u32 size;
	/* Union selected by type. */
	union {
		mali_mem_os_mem os_mem;       /**< MALI_MEM_OS */
		mali_mem_external ext_mem;    /**< MALI_MEM_EXTERNAL */
		mali_mem_dma_buf dma_buf;     /**< MALI_MEM_DMA_BUF */
		mali_mem_ump ump_mem;         /**< MALI_MEM_UMP */
		mali_mem_block_mem block_mem; /**< MALI_MEM_BLOCK */
		mali_mem_cow cow_mem;
	};
	mali_mem_allocation *mali_allocation;
	struct mutex mutex;
	mali_mem_type cow_type;

	u32 cow_flag;
} mali_mem_backend;

#define MALI_MEM_FLAG_MALI_GUARD_PAGE (1 << 0)
#define MALI_MEM_FLAG_DONT_CPU_MAP    (1 << 1)

#endif /* __MALI_MEMORY_TYPES__ */
