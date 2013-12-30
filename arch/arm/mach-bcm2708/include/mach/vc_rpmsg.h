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

#ifndef VC_RPMSG_MACH_H
#define VC_RPMSG_MACH_H

/* There are 4 doorbell interrupts. 0 and 1 signal from VC to ARM,
 * while 2 and 3 signal from ARM to VC.
 *
 * VCHIQ uses doorbells 0 (VC->ARM) and 2 (ARM->VC).
 * RPMSG uses doorbells 1 (VC->ARM) and 3 (ARM->VC).
 *
 * Interrupts are cleared automatically by reading from them.
 *
 * In theory rpmsg and vchiq could share a doorbell. However, this
 * could potentially lead to reduced vchiq performance while doing rpmsg
 * operations.
 */


/* Doorbell signalled from VC */
#define VC_RPMSG_IRQ IRQ_ARM_DOORBELL_1
#define VC_RPMSG_2835_FROM_VC_BELL  ARM_0_BELL1
#define VC_RPMSG_2835_TO_VC_BELL    ARM_0_BELL3

/* VC->ARM interrupt for ARM's rx vring */
#define VC_RPMSG_IPC_DOORBELL_HOST_RX_TO_ARM    1
/* VC->ARM interrupt for ARM's tx vring */
#define VC_RPMSG_IPC_DOORBELL_HOST_TX_TO_ARM    1
/* ARM->VC interrupt for ARM's rx vring */
#define VC_RPMSG_IPC_DOORBELL_HOST_RX_FROM_ARM  3
/* ARM->VC interrupt for ARM's tx vring */
#define VC_RPMSG_IPC_DOORBELL_HOST_TX_FROM_ARM  3

#define VC_RPMSG_DOORBELL_MASK \
	((1 << VC_RPMSG_IPC_DOORBELL_HOST_RX_TO_ARM) | \
	 (1 << VC_RPMSG_IPC_DOORBELL_HOST_TX_TO_ARM))

void vc_rpmsg_doorbell_signal_rx(void);
void vc_rpmsg_doorbell_signal_tx(void);
void vc_rpmsg_doorbell_init(void);
unsigned vc_rpmsg_doorbell_status(void);
void vc_rpmsg_doorbell_clear(unsigned bell);

#endif
