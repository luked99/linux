/*
 * Copyright (c) 2010-2012 Broadcom. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/cdev.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/ioctl.h>
#include <linux/semaphore.h>
#include <linux/proc_fs.h>
#include <linux/dma-mapping.h>
#include <linux/pfn.h>
#include <linux/hugetlb.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <mach/vc_mem.h>

#include "debug_sym.h"
#include "linux/broadcom/vc_debug_sym.h"

#ifndef PAGE_SIZE
#define PAGE_SIZE   4096
#define PAGE_MASK   (~(PAGE_SIZE - 1))
#endif

/* Offset within the videocore memory map to get the address of the symbol
 * table.
 */
#define VC_SYMBOL_BASE_OFFSET       VC_DEBUG_HEADER_OFFSET

struct vc_mem_access_handle {
	int memFd;
	VC_MEM_ADDR_T vcMemBase;	/* start of the loaded image */
	VC_MEM_ADDR_T vcMemLoad;	/* start of the running image */
	VC_MEM_ADDR_T vcMemEnd;	/* end of the loaded image */
	size_t vcMemSize;	/* amount of memory used */
	VC_MEM_ADDR_T vcMemPhys;	/* memory physical address */

	VC_MEM_ADDR_T vcSymbolTableOffset;
	unsigned numSymbols;
	struct vc_debug_symbol *symbol;
};

#define DBG(fmt, ...)
/* #define DBG( fmt, ... ) \
printk( KERN_DEBUG  "[D]:%s: " fmt "\n", __func__, ##__VA_ARGS__ ) */
#define ERR(fmt, ...) \
	pr_err("[E]:%s: " fmt "\n", __func__, ##__VA_ARGS__)

enum MEM_OP_T {
	READ_MEM,
	WRITE_MEM,
};

/****************************************************************************
*
*   Get access to the videocore memory space. Returns zero if the memory was
*   opened successfully.
*
***************************************************************************/

int OpenVideoCoreMemory(struct vc_mem_access_handle **vcHandlePtr)
{
	return OpenVideoCoreMemoryFile(NULL, vcHandlePtr);
}
EXPORT_SYMBOL(OpenVideoCoreMemory);

/****************************************************************************
*
*   Get access to the videocore memory space. Returns zero if the memory was
*   opened successfully.
*
***************************************************************************/

int OpenVideoCoreMemoryFile(const char *filename,
			    struct vc_mem_access_handle **vcHandlePtr)
{
	int rc = 0;
	struct vc_mem_access_handle *newHandle;
	struct vc_debug_symbol debug_sym;
	VC_MEM_ADDR_T symAddr;
	size_t symTableSize;
	unsigned symIdx;

	newHandle = kzalloc(sizeof(*newHandle), GFP_KERNEL);
	if (newHandle == NULL)
		return -ENOMEM;

	newHandle->vcMemSize = vc_mem_get_current_size();
	newHandle->vcMemBase = vc_mem_get_current_base();
	newHandle->vcMemLoad = vc_mem_get_current_load();
	newHandle->vcMemPhys = 0;

	DBG("vcMemSize = %zu\n", newHandle->vcMemSize);
	DBG("vcMemBase = %zu\n", newHandle->vcMemBase);
	DBG("vcMemLoad = %zu\n", newHandle->vcMemLoad);
	DBG("vcMemPhys = %zu\n", newHandle->vcMemPhys);

	newHandle->vcMemEnd = newHandle->vcMemBase + newHandle->vcMemSize - 1;

	/* See if we can detect the symbol table
	 */

	if (!ReadVideoCoreMemory(newHandle,
				 &newHandle->vcSymbolTableOffset,
				 newHandle->vcMemLoad + VC_SYMBOL_BASE_OFFSET,
				 sizeof(newHandle->vcSymbolTableOffset))) {
		ERR("%s: @VC_SYMBOL_BASE_OFFSET (0x%08x) failed\n",
		    __func__,
		    VC_SYMBOL_BASE_OFFSET);
		rc = -EIO;
		goto err_exit;
	}

	DBG("vcSymbolTableOffset = 0x%08x", newHandle->vcSymbolTableOffset);

	/* Make sure that the pointer points into the first few megabytes of
	 * the memory space.
	 */

	if ((newHandle->vcSymbolTableOffset - newHandle->vcMemLoad) >
	    (8 * 1024 * 1024)) {
		ERR("newHandle->vcSymbolTableOffset (%d) > 8Mb\n",
		    newHandle->vcSymbolTableOffset);
		rc = -EIO;
		goto err_exit;
	}

	/* Make a pass to count how many symbols there are.
	 */
	symAddr = newHandle->vcSymbolTableOffset;
	newHandle->numSymbols = 0;
	do {
		if (!ReadVideoCoreMemory(newHandle,
					 &debug_sym,
					 symAddr, sizeof(debug_sym))) {
			ERR("ReadVideoCoreMemory @ symAddr(0x%08x) failed\n",
			    symAddr);
			rc = -EIO;
			goto err_exit;
		}

		newHandle->numSymbols++;

		DBG("Symbol %d: label: 0x%p addr: 0x%08x size: %zu",
		    newHandle->numSymbols,
		    debug_sym.label, debug_sym.addr, debug_sym.size);

		if (newHandle->numSymbols > 1024) {
			ERR("numSymbols (%d) > 1024 - looks wrong\n",
			    newHandle->numSymbols);
			rc = -EIO;
			goto err_exit;
		}
		symAddr += sizeof(debug_sym);

	} while (debug_sym.label != 0);
	newHandle->numSymbols--;

	DBG("Detected %d symbols", newHandle->numSymbols);

	/* Allocate some memory to hold the symbols, and read them in.
	 */

	symTableSize = newHandle->numSymbols * sizeof(debug_sym);

	newHandle->symbol = kzalloc(symTableSize, GFP_KERNEL);
	if (newHandle->symbol == NULL) {
		rc = -ENOMEM;
		goto err_exit;
	}
	if (!ReadVideoCoreMemory(newHandle,
				 newHandle->symbol,
				 newHandle->vcSymbolTableOffset,
				 symTableSize)) {
		ERR("%s: @ newHandle->vcSymbolTableOffset(0x%08x) failed\n",
		    __func__,
		    newHandle->vcSymbolTableOffset);
		rc = -EIO;
		goto err_exit;
	}

	/* The names of the symbols are pointers in videocore space. We want
	 * to have them available locally, so we make copies and fixup
	 * the pointer.
	 */
	for (symIdx = 0; symIdx < newHandle->numSymbols; symIdx++) {
		struct vc_debug_symbol *sym;
		char symName[256];

		sym = &newHandle->symbol[symIdx];

		DBG("Symbol %d: label: 0x%p addr: 0x%08x size: %zu",
		    symIdx, sym->label, sym->addr, sym->size);

		if (!ReadVideoCoreMemory(newHandle,
					 symName,
					 TO_VC_MEM_ADDR(sym->label),
					 sizeof(symName))) {
			ERR("ReadVideoCoreMemory @ sym->label(0x%08x) failed\n",
			    sym->addr);
			rc = -EIO;
			goto err_exit;
		}
		symName[sizeof(symName) - 1] = '\0';
		*((const char **)&sym->label) = kstrdup(symName, GFP_KERNEL);

		if (!sym->label) {
			ERR("Memory allocation failed\n");
			rc = -ENOMEM;
			goto err_exit;
		}

		DBG("Symbol %d (@0x%p): label: '%s' addr: 0x%08x size: %zu",
		    symIdx, sym, sym->label, sym->addr, sym->size);
	}

	*vcHandlePtr = newHandle;
	return 0;

err_exit:
	kfree(newHandle);

	return rc;
}
EXPORT_SYMBOL(OpenVideoCoreMemoryFile);

/****************************************************************************
*
*   Returns the number of symbols which were detected.
*
***************************************************************************/

unsigned NumVideoCoreSymbols(struct vc_mem_access_handle *vcHandle)
{
	return vcHandle->numSymbols;
}
EXPORT_SYMBOL(NumVideoCoreSymbols);

/****************************************************************************
*
*   Returns the name, address and size of the i'th symbol.
*
***************************************************************************/

int GetVideoCoreSymbol(struct vc_mem_access_handle *vcHandle, unsigned idx,
		       char *labelBuf, size_t labelBufSize,
		       VC_MEM_ADDR_T *vcMemAddr, size_t *vcMemSize)
{
	struct vc_debug_symbol *sym;

	if (idx >= vcHandle->numSymbols)
		return -EINVAL;

	sym = &vcHandle->symbol[idx];

	strncpy(labelBuf, sym->label, labelBufSize);
	labelBuf[labelBufSize - 1] = '\0';

	if (vcMemAddr != NULL)
		*vcMemAddr = (VC_MEM_ADDR_T) sym->addr;

	if (vcMemSize != NULL)
		*vcMemSize = sym->size;

	return 0;
}
EXPORT_SYMBOL(GetVideoCoreSymbol);

/****************************************************************************
*
*   Looks up the named, symbol. If the symbol is found, it's value and size
*   are returned.
*
*   Returns  true if the lookup was successful.
*
***************************************************************************/

int LookupVideoCoreSymbol(struct vc_mem_access_handle *vcHandle, const char *symbol,
			  VC_MEM_ADDR_T *vcMemAddr, size_t *vcMemSize)
{
	unsigned idx;
	char symName[64];
	VC_MEM_ADDR_T symAddr = 0;
	size_t symSize = 0;

	for (idx = 0; idx < vcHandle->numSymbols; idx++) {
		GetVideoCoreSymbol(vcHandle, idx, symName, sizeof(symName),
				   &symAddr, &symSize);
		if (strcmp(symbol, symName) == 0) {
			if (vcMemAddr != NULL)
				*vcMemAddr = symAddr;

			if (vcMemSize != 0)
				*vcMemSize = symSize;

			DBG("%s found, addr = 0x%08x size = %zu", symbol,
			    symAddr, symSize);
			return 1;
		}
	}

	if (vcMemAddr != NULL)
		*vcMemAddr = 0;

	if (vcMemSize != 0)
		*vcMemSize = 0;

	DBG("%s not found", symbol);
	return 0;
}
EXPORT_SYMBOL(LookupVideoCoreSymbol);

/****************************************************************************
*
*   Looks up the named, symbol. If the symbol is found, and it's size is equal
*   to the sizeof a uint32_t, then true is returned.
*
***************************************************************************/

int LookupVideoCoreUInt32Symbol(struct vc_mem_access_handle *vcHandle,
				const char *symbol, VC_MEM_ADDR_T *vcMemAddr)
{
	size_t vcMemSize;

	if (!LookupVideoCoreSymbol(vcHandle, symbol, vcMemAddr, &vcMemSize))
		return 0;

	if (vcMemSize != sizeof(uint32_t)) {
		ERR("Symbol: '%s' has a size of %zu, expecting %zu", symbol,
		    vcMemSize, sizeof(uint32_t));
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(LookupVideoCoreUInt32Symbol);

/****************************************************************************
*
*   Does Reads or Writes on the videocore memory.
*
***************************************************************************/

static int AccessVideoCoreMemory(struct vc_mem_access_handle *vcHandle,
				 enum MEM_OP_T mem_op,
				 void *buf,
				 VC_MEM_ADDR_T vcMemAddr, size_t numBytes)
{
	DBG("%s %zu bytes @ 0x%08x", mem_op == WRITE_MEM ? "Write" : "Read",
	    numBytes, vcMemAddr);

	/*
	 * Since we'll be passed videocore pointers,
	 * we need to deal with the high bits.
	 *
	 * We need to strip off the high 2 bits to convert to
	 * a physical address, except for when the high 3 bits are
	 * equal to 011, which means that it corresponds to
	 * a peripheral and isn't accessible.
	 */

	if (IS_ALIAS_PERIPHERAL(vcMemAddr)) {
		/* This is a peripheral address.
		 */
		ERR("Can't access peripheral address 0x%08x", vcMemAddr);
		return 0;
	}
	vcMemAddr = TO_VC_MEM_ADDR(ALIAS_NORMAL(vcMemAddr));

	if ((vcMemAddr < vcHandle->vcMemBase) ||
	    (vcMemAddr > vcHandle->vcMemEnd)) {
		ERR("Memory address 0x%08x is outside range 0x%08x-0x%08x",
		    vcMemAddr, vcHandle->vcMemBase, vcHandle->vcMemEnd);
		return 0;
	}
	if ((vcMemAddr + numBytes - 1) > vcHandle->vcMemEnd) {
		ERR("Address 0x%08x + numBytes 0x%08zx is > memory end 0x%08x",
			vcMemAddr, numBytes, vcHandle->vcMemEnd);
		return 0;
	}

	if (vc_mem_access_mem(mem_op == WRITE_MEM, buf, vcMemAddr, numBytes) !=
	    0) {
		return 0;
	}

	return 1;
}

/****************************************************************************
*
*   Reads 'numBytes' from the videocore memory starting at 'vcMemAddr'. The
*   results are stored in 'buf'.
*
*   Returns true if the read was successful.
*
***************************************************************************/

int ReadVideoCoreMemory(struct vc_mem_access_handle *vcHandle, void *buf,
			VC_MEM_ADDR_T vcMemAddr, size_t numBytes)
{
	return AccessVideoCoreMemory(vcHandle, READ_MEM, buf, vcMemAddr,
				     numBytes);
}
EXPORT_SYMBOL(ReadVideoCoreMemory);

/****************************************************************************
*
*   Reads 'numBytes' from the videocore memory starting at 'vcMemAddr'. The
*   results are stored in 'buf'.
*
*   Returns true if the read was successful.
*
***************************************************************************/

int ReadVideoCoreMemoryBySymbol(struct vc_mem_access_handle *vcHandle,
				const char *symbol, void *buf, size_t bufSize)
{
	VC_MEM_ADDR_T vcMemAddr;
	size_t vcMemSize;

	if (!LookupVideoCoreSymbol(vcHandle, symbol, &vcMemAddr, &vcMemSize)) {
		ERR("Symbol not found: '%s'", symbol);
		return 0;
	}

	if (vcMemSize > bufSize)
		vcMemSize = bufSize;

	if (!ReadVideoCoreMemory(vcHandle, buf, vcMemAddr, vcMemSize)) {
		ERR("Unable to read %zu bytes @ 0x%08x", vcMemSize, vcMemAddr);
		return 0;
	}
	return 1;
}
EXPORT_SYMBOL(ReadVideoCoreMemoryBySymbol);

/****************************************************************************
*
*   Looks up a symbol and reads the contents into a user supplied buffer.
*
*   Returns true if the read was successful.
*
***************************************************************************/

int ReadVideoCoreStringBySymbol(struct vc_mem_access_handle *vcHandle,
				const char *symbol, char *buf, size_t bufSize)
{
	VC_MEM_ADDR_T vcMemAddr;
	size_t vcMemSize;

	if (!LookupVideoCoreSymbol(vcHandle, symbol, &vcMemAddr, &vcMemSize)) {
		ERR("Symbol not found: '%s'", symbol);
		return 0;
	}

	if (vcMemSize > bufSize)
		vcMemSize = bufSize;

	if (!ReadVideoCoreMemory(vcHandle, buf, vcMemAddr, vcMemSize)) {
		ERR("Unable to read %zu bytes @ 0x%08x", vcMemSize, vcMemAddr);
		return 0;
	}

	/* Make sure that the result is null-terminated
	 */

	buf[vcMemSize - 1] = '\0';
	return 1;
}
EXPORT_SYMBOL(ReadVideoCoreStringBySymbol);

/****************************************************************************
*
*   Writes 'numBytes' into the videocore memory starting at 'vcMemAddr'. The
*   data is taken from 'buf'.
*
*   Returns true if the write was successful.
*
***************************************************************************/

int WriteVideoCoreMemory(struct vc_mem_access_handle *vcHandle,
			 void *buf, VC_MEM_ADDR_T vcMemAddr, size_t numBytes)
{
	return AccessVideoCoreMemory(vcHandle, WRITE_MEM, buf, vcMemAddr,
				     numBytes);
}
EXPORT_SYMBOL(WriteVideoCoreMemory);

/****************************************************************************
*
*   Closes the memory space opened previously via OpenVideoCoreMemory.
*
***************************************************************************/

void CloseVideoCoreMemory(struct vc_mem_access_handle *vcHandle)
{
	unsigned symIdx;
	struct vc_debug_symbol *sym;

	if (!vcHandle) {
		ERR("NULL reference at vcHandle!!!\n");
		return;
	}

	if (vcHandle->symbol) {
		for (symIdx = 0; symIdx < vcHandle->numSymbols; symIdx++) {
			sym = &vcHandle->symbol[symIdx];
			if (sym && sym->label)
				kfree(sym->label);
		}
		kfree(vcHandle->symbol);
	}
	kfree(vcHandle);
}
EXPORT_SYMBOL(CloseVideoCoreMemory);

/****************************************************************************
*
*   Returns the size of the videocore memory space.
*
***************************************************************************/

size_t GetVideoCoreMemorySize(struct vc_mem_access_handle *vcHandle)
{
	return vcHandle->vcMemSize;
}
EXPORT_SYMBOL(GetVideoCoreMemorySize);

/****************************************************************************
*
*   Returns the videocore memory physical address.
*
***************************************************************************/

void *GetVideoCoreMemoryPhysicalAddress(struct vc_mem_access_handle *vcHandle)
{
	return (void *)vcHandle->vcMemPhys;
}
EXPORT_SYMBOL(GetVideoCoreMemoryPhysicalAddress);
