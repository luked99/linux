/*
 * Copyright (C) 2013 Broadcom Corporation
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

#include <mach/vc_rpmsg.h>
#include <linux/module.h>
#include <linux/io.h>
#include <mach/vcio.h>
#include <mach/platform.h>

void vc_rpmsg_doorbell_signal_rx(void)
{
	pr_debug("%s\n", __func__);
	writel(0, __io_address(VC_RPMSG_2835_TO_VC_BELL));
}
EXPORT_SYMBOL(vc_rpmsg_doorbell_signal_rx);

void vc_rpmsg_doorbell_signal_tx(void)
{
	pr_debug("%s\n", __func__);
	writel(0, __io_address(VC_RPMSG_2835_TO_VC_BELL));
}
EXPORT_SYMBOL(vc_rpmsg_doorbell_signal_tx);

void vc_rpmsg_doorbell_init(void)
{
}
EXPORT_SYMBOL(vc_rpmsg_doorbell_init);

/* Read and clear the doorbell. A status of 4 means it was rung.
 * The lower bits indicate the 'owner' (which is not used).
 *
 * Because the interrupt is shared, and we cannot pass any bits
 * across, we just pretend both RX and TX were signalled.
 */
unsigned vc_rpmsg_doorbell_status(void)
{
	uint32_t status = readl(__io_address(VC_RPMSG_2835_FROM_VC_BELL));
	pr_debug("%s: status 0x%x\n", __func__, status);
	return VC_RPMSG_DOORBELL_MASK;
}
EXPORT_SYMBOL(vc_rpmsg_doorbell_status);

void vc_rpmsg_doorbell_clear(unsigned bell)
{
	(void)bell;
}
EXPORT_SYMBOL(vc_rpmsg_doorbell_clear);
