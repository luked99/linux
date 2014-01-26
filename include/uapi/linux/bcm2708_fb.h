/*
 *  linux/drivers/video/bcm2708_fb.h
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file COPYING in the main directory of this archive
 * for more details.
 *
 * Copyright (C) 2014 Luke Diamand <luke@diamand.org>
 *
 * Definitions of device-specific ioctls for the BCM2708 framebuffer driver.
 *
 */

#ifndef _UAPI_LINUX_BCM2708_FB_H
#define _UAPI_LINUX_BCM2708_FB_H

struct bcm2708_fb_fillrect {
	__u32 dx;	/* screen-relative */
	__u32 dy;
	__u32 width;
	__u32 height;
	__u32 color;	/* pixel values */
	__u32 rop;
};

#define BCM2708_FB_IOC_MAGIC	'z'

#define BCM2708_FB_IO_FILLRECT	\
	_IOW(BCM2708_FB_IOC_MAGIC, 0x22, struct fb_fillrect)

#endif
