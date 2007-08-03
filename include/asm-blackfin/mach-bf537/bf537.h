/*
 * File:         include/asm-blackfin/mach-bf537/bf537.h
 * Based on:
 * Author:
 *
 * Created:
 * Description:  SYSTEM MMR REGISTER AND MEMORY MAP FOR ADSP-BF537
 *
 * Modified:
 *               Copyright 2004-2006 Analog Devices Inc.
 *
 * Bugs:         Enter bugs at http://blackfin.uclinux.org/
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
 * along with this program; if not, see the file COPYING, or write
 * to the Free Software Foundation, Inc.,
 * 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef __MACH_BF537_H__
#define __MACH_BF537_H__

#define SUPPORTED_REVID 2

/* Masks for generic ERROR IRQ demultiplexing used in int-priority-sc.c */

#define SPI_ERR_MASK (TXCOL | RBSY | MODF | TXE)	/* SPI_STAT */
#define SPORT_ERR_MASK (ROVF | RUVF | TOVF | TUVF)	/* SPORTx_STAT */
#define PPI_ERR_MASK (0xFFFF & ~FLD)	/* PPI_STATUS */
#define EMAC_ERR_MASK (PHYINT | MMCINT | RXFSINT | TXFSINT | WAKEDET | RXDMAERR | TXDMAERR | STMDONE)	/* EMAC_SYSTAT */
#define UART_ERR_MASK_STAT1 (0x4)	/* UARTx_IIR */
#define UART_ERR_MASK_STAT0 (0x2)	/* UARTx_IIR */
#define CAN_ERR_MASK  (EWTIF | EWRIF | EPIF | BOIF | WUIF | UIAIF | AAIF | RMLIF | UCEIF | EXTIF | ADIF)	/* CAN_GIF */

#define OFFSET_(x) ((x) & 0x0000FFFF)

/*some misc defines*/
#define IMASK_IVG15		0x8000
#define IMASK_IVG14		0x4000
#define IMASK_IVG13		0x2000
#define IMASK_IVG12		0x1000

#define IMASK_IVG11		0x0800
#define IMASK_IVG10		0x0400
#define IMASK_IVG9		0x0200
#define IMASK_IVG8		0x0100

#define IMASK_IVG7		0x0080
#define IMASK_IVGTMR	0x0040
#define IMASK_IVGHW		0x0020

/***************************/


#define BLKFIN_DSUBBANKS	4
#define BLKFIN_DWAYS		2
#define BLKFIN_DLINES		64
#define BLKFIN_ISUBBANKS	4
#define BLKFIN_IWAYS		4
#define BLKFIN_ILINES		32

#define WAY0_L			0x1
#define WAY1_L			0x2
#define WAY01_L			0x3
#define WAY2_L			0x4
#define WAY02_L			0x5
#define	WAY12_L			0x6
#define	WAY012_L		0x7

#define	WAY3_L			0x8
#define	WAY03_L			0x9
#define	WAY13_L			0xA
#define	WAY013_L		0xB

#define	WAY32_L			0xC
#define	WAY320_L		0xD
#define	WAY321_L		0xE
#define	WAYALL_L		0xF

#define DMC_ENABLE (2<<2)	/*yes, 2, not 1 */

/********************************* EBIU Settings ************************************/
#define AMBCTL0VAL	((CONFIG_BANK_1 << 16) | CONFIG_BANK_0)
#define AMBCTL1VAL	((CONFIG_BANK_3 << 16) | CONFIG_BANK_2)

#ifdef CONFIG_C_AMBEN_ALL
#define V_AMBEN AMBEN_ALL
#endif
#ifdef CONFIG_C_AMBEN
#define V_AMBEN 0x0
#endif
#ifdef CONFIG_C_AMBEN_B0
#define V_AMBEN AMBEN_B0
#endif
#ifdef CONFIG_C_AMBEN_B0_B1
#define V_AMBEN AMBEN_B0_B1
#endif
#ifdef CONFIG_C_AMBEN_B0_B1_B2
#define V_AMBEN AMBEN_B0_B1_B2
#endif
#ifdef CONFIG_C_AMCKEN
#define V_AMCKEN AMCKEN
#else
#define V_AMCKEN 0x0
#endif
#ifdef CONFIG_C_CDPRIO
#define V_CDPRIO 0x100
#else
#define V_CDPRIO 0x0
#endif

#define AMGCTLVAL	(V_AMBEN | V_AMCKEN | V_CDPRIO)

#ifdef CONFIG_BF537
#define CPU "BF537"
#define CPUID 0x027c8000
#endif
#ifdef CONFIG_BF536
#define CPU "BF536"
#define CPUID 0x027c8000
#endif
#ifdef CONFIG_BF534
#define CPU "BF534"
#define CPUID 0x027c6000
#endif
#ifndef CPU
#define	CPU "UNKNOWN"
#define CPUID 0x0
#endif

#if (CONFIG_MEM_SIZE % 4)
#error "SDRAM mem size must be multible of 4MB"
#endif

#define SDRAM_IGENERIC    (CPLB_L1_CHBL | CPLB_USER_RD | CPLB_VALID | CPLB_PORTPRIO)
#define SDRAM_IKERNEL     (SDRAM_IGENERIC | CPLB_LOCK)
#define L1_IMEMORY        (               CPLB_USER_RD | CPLB_VALID | CPLB_LOCK)
#define SDRAM_INON_CHBL   (               CPLB_USER_RD | CPLB_VALID)

/*Use the menuconfig cache policy here - CONFIG_BLKFIN_WT/CONFIG_BLKFIN_WB*/

#define ANOMALY_05000158_WORKAROUND		0x200
#ifdef CONFIG_BLKFIN_WB		/*Write Back Policy */
#define SDRAM_DGENERIC   (CPLB_L1_CHBL | CPLB_DIRTY \
			| CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID | ANOMALY_05000158_WORKAROUND)
#else				/*Write Through */
#define SDRAM_DGENERIC   (CPLB_L1_CHBL | CPLB_WT | CPLB_L1_AOW \
			| CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID | ANOMALY_05000158_WORKAROUND | CPLB_DIRTY )
#endif


#define L1_DMEMORY       (CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID | ANOMALY_05000158_WORKAROUND | CPLB_LOCK | CPLB_DIRTY )
#define SDRAM_DNON_CHBL  (CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID | ANOMALY_05000158_WORKAROUND | CPLB_DIRTY )
#define SDRAM_EBIU       (CPLB_SUPV_WR | CPLB_USER_WR | CPLB_USER_RD | CPLB_VALID | ANOMALY_05000158_WORKAROUND | CPLB_DIRTY )
#define SDRAM_OOPS  	 (CPLB_VALID | ANOMALY_05000158_WORKAROUND | CPLB_LOCK | CPLB_DIRTY )

#define SIZE_1K 0x00000400	/* 1K */
#define SIZE_4K 0x00001000	/* 4K */
#define SIZE_1M 0x00100000	/* 1M */
#define SIZE_4M 0x00400000	/* 4M */

#define MAX_CPLBS (16 * 2)

/*
* Number of required data CPLB switchtable entries
* MEMSIZE / 4 (we mostly install 4M page size CPLBs
* approx 16 for smaller 1MB page size CPLBs for allignment purposes
* 1 for L1 Data Memory
* 1 for CONFIG_DEBUG_HUNT_FOR_ZERO
* 1 for ASYNC Memory
*/


#define MAX_SWITCH_D_CPLBS (((CONFIG_MEM_SIZE / 4) + 16 + 1 + 1 + 1) * 2)

/*
* Number of required instruction CPLB switchtable entries
* MEMSIZE / 4 (we mostly install 4M page size CPLBs
* approx 12 for smaller 1MB page size CPLBs for allignment purposes
* 1 for L1 Instruction Memory
* 1 for CONFIG_DEBUG_HUNT_FOR_ZERO
*/

#define MAX_SWITCH_I_CPLBS (((CONFIG_MEM_SIZE / 4) + 12 + 1 + 1) * 2)

#endif				/* __MACH_BF537_H__  */
