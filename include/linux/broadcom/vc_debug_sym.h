/*****************************************************************************
* Copyright 2001 - 2010 Broadcom Corporation.  All rights reserved.
*
* Unless you and Broadcom execute a separate written software license
* agreement governing use of this software, this software is licensed to you
* under the terms of the GNU General Public License version 2, available at
* http://www.broadcom.com/licenses/GPLv2.php (the "GPL").
*
* Notwithstanding the above, under no circumstances may you combine this
* software in any way with any other Broadcom software provided under a
* license other than the GPL, without Broadcom's express prior written
* consent.
*****************************************************************************/

#if !defined(VC_DEBUG_SYM_H)
#define VC_DEBUG_SYM_H

/* ---- Include Files ----------------------------------------------------- */

#include <stddef.h>
#if defined(__KERNEL__)
#include <linux/types.h>	/* Needed for standard types */
#else
#include <stdint.h>
#endif

/* ---- Constants and Types ---------------------------------------------- */

struct vc_debug_symbol {
	const char *label;
	uint32_t addr;
	size_t size;

};

struct vc_debug_header {
	uint32_t symbolTableOffset;
	uint32_t magic;
	uint32_t paramSize;
};

struct vc_debug_params {
	uint32_t vcMemBase;
	uint32_t vcMemSize;
	uint32_t vcEntryPoint;
	uint32_t symbolTableLength;
};

#define VC_DEBUG_HEADER_MAGIC\
	(('V' << 0) + ('C' << 8) + ('D' << 16) + ('H' << 24))

/* Offset within the videocore memory map to get the address
of the debug header.*/
#define VC_DEBUG_HEADER_OFFSET 0x2800


#define  USE_VC_DEBUG_SYMS   1

/* ---- Function Prototypes ---------------------------------------------- */

#endif /* VC_DEBUG_SYM_H */
