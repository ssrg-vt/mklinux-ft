/*
 * file:	include/asm-blackfin/mach-bf548/irq.h
 * based on:	include/asm-blackfin/mach-bf537/irq.h 
 * author:	Roy Huang (roy.huang@analog.com)
 *
 * created:
 * description:
 *	system mmr register map
 * rev:
 *
 * modified:
 *
 *
 * bugs:         enter bugs at http://blackfin.uclinux.org/
 *
 * this program is free software; you can redistribute it and/or modify
 * it under the terms of the gnu general public license as published by
 * the free software foundation; either version 2, or (at your option)
 * any later version.
 *
 * this program is distributed in the hope that it will be useful,
 * but without any warranty; without even the implied warranty of
 * merchantability or fitness for a particular purpose.  see the
 * gnu general public license for more details.
 *
 * you should have received a copy of the gnu general public license
 * along with this program; see the file copying.
 * if not, write to the free software foundation,
 * 59 temple place - suite 330, boston, ma 02111-1307, usa.
 */

#ifndef _BF548_IRQ_H_
#define _BF548_IRQ_H_

/*
 * Interrupt source definitions
            Event Source    Core Event Name
Core        Emulation               **
Events         (highest priority)  EMU         0
            Reset                   RST         1
            NMI                     NMI         2
            Exception               EVX         3
            Reserved                --          4
            Hardware Error          IVHW        5
            Core Timer              IVTMR       6 *

.....

            Software Interrupt 1    IVG14       31
            Software Interrupt 2    --
                 (lowest priority)  IVG15       32 *
 */

#define NR_PERI_INTS    32

/* The ABSTRACT IRQ definitions */
/** the first seven of the following are fixed, the rest you change if you need to **/
#define IRQ_EMU		0	/* Emulation */
#define IRQ_RST		1	/* reset */
#define IRQ_NMI		2	/* Non Maskable */
#define IRQ_EVX		3	/* Exception */
#define IRQ_UNUSED	4	/* - unused interrupt*/
#define IRQ_HWERR	5	/* Hardware Error */
#define IRQ_CORETMR	6	/* Core timer */

#define BFIN_IRQ(x)	((x) + 7)

#define IRQ_PLL_WAKEUP	BFIN_IRQ(0)	/* PLL Wakeup Interrupt */
#define IRQ_DMAC0_ERR	BFIN_IRQ(1)	/* DMAC0 Status Interrupt */
#define IRQ_EPPI0_ERR	BFIN_IRQ(2)	/* EPPI0 Error Interrupt */
#define IRQ_SPORT0_ERR	BFIN_IRQ(3)	/* SPORT0 Error Interrupt */
#define IRQ_SPORT1_ERR	BFIN_IRQ(4)	/* SPORT1 Error Interrupt */
#define IRQ_SPI0_ERR	BFIN_IRQ(5)	/* SPI0 Status(Error) Interrupt */
#define IRQ_UART0_ERR	BFIN_IRQ(6)	/* UART0 Status(Error) Interrupt */
#define IRQ_RTC		BFIN_IRQ(7)	/* RTC Interrupt */
#define IRQ_EPPI0	BFIN_IRQ(8)	/* EPPI0 Interrupt (DMA12) */
#define IRQ_SPORT0_RX	BFIN_IRQ(9)	/* SPORT0 RX Interrupt (DMA0) */
#define IRQ_SPORT0_TX	BFIN_IRQ(10)	/* SPORT0 TX Interrupt (DMA1) */
#define IRQ_SPORT1_RX	BFIN_IRQ(11)	/* SPORT1 RX Interrupt (DMA2) */
#define IRQ_SPORT1_TX	BFIN_IRQ(12)	/* SPORT1 TX Interrupt (DMA3) */
#define IRQ_SPI0	BFIN_IRQ(13)	/* SPI0 Interrupt (DMA4) */
#define IRQ_UART0_RX	BFIN_IRQ(14)	/* UART0 RX Interrupt (DMA6) */
#define IRQ_UART0_TX	BFIN_IRQ(15)	/* UART0 TX Interrupt (DMA7) */
#define IRQ_TIMER8	BFIN_IRQ(16)	/* TIMER 8 Interrupt */
#define IRQ_TIMER9	BFIN_IRQ(17)	/* TIMER 9 Interrupt */
#define IRQ_TIMER10	BFIN_IRQ(18)	/* TIMER 10 Interrupt */
#define IRQ_PINT0	BFIN_IRQ(19)	/* PINT0 Interrupt */
#define IRQ_PINT1	BFIN_IRQ(20)	/* PINT1 Interrupt */
#define IRQ_MDMAS0	BFIN_IRQ(21)	/* MDMA Stream 0 Interrupt */
#define IRQ_MDMAS1	BFIN_IRQ(22)	/* MDMA Stream 1 Interrupt */
#define IRQ_WATCHDOG	BFIN_IRQ(23)	/* Watchdog Interrupt */
#define IRQ_DMAC1_ERR	BFIN_IRQ(24)	/* DMAC1 Status (Error) Interrupt */
#define IRQ_SPORT2_ERR	BFIN_IRQ(25)	/* SPORT2 Error Interrupt */
#define IRQ_SPORT3_ERR	BFIN_IRQ(26)	/* SPORT3 Error Interrupt */
#define IRQ_MXVR	BFIN_IRQ(27)	/* SPORT3 Error Interrupt */
#define IRQ_SPI1_ERR	BFIN_IRQ(28)	/* SPI1 Status (Error) Interrupt */
#define IRQ_SPI2_ERR	BFIN_IRQ(29)	/* SPI2 Status (Error) Interrupt */
#define IRQ_UART1_ERR	BFIN_IRQ(30)	/* UART1 Status (Error) Interrupt */
#define IRQ_UART2_ERR	BFIN_IRQ(31)	/* UART2 Status (Error) Interrupt */
#define IRQ_CAN0_ERR	BFIN_IRQ(32)	/* CAN0 Status (Error) Interrupt */
#define IRQ_SPORT2_RX	BFIN_IRQ(33)	/* SPORT2 RX (DMA18) Interrupt */
#define IRQ_SPORT2_TX	BFIN_IRQ(34)	/* SPORT2 TX (DMA19) Interrupt */
#define IRQ_SPORT3_RX	BFIN_IRQ(35)	/* SPORT3 RX (DMA20) Interrupt */
#define IRQ_SPORT3_TX	BFIN_IRQ(36)	/* SPORT3 TX (DMA21) Interrupt */
#define IRQ_EPP1	BFIN_IRQ(37)	/* EPP1 (DMA13) Interrupt */
#define IRQ_EPP2	BFIN_IRQ(38)	/* EPP2 (DMA14) Interrupt */
#define IRQ_SPI1	BFIN_IRQ(39)	/* SPI1 (DMA5) Interrupt */
#define IRQ_SPI2	BFIN_IRQ(40)	/* SPI2 (DMA23) Interrupt */
#define IRQ_UART1_RX	BFIN_IRQ(41)	/* UART1 RX (DMA8) Interrupt */
#define IRQ_UART1_TX	BFIN_IRQ(42)	/* UART1 TX (DMA9) Interrupt */
#define IRQ_ATAPI_RX	BFIN_IRQ(43)	/* ATAPI RX (DMA10) Interrupt */
#define IRQ_ATAPI_TX	BFIN_IRQ(44)	/* ATAPI TX (DMA11) Interrupt */
#define IRQ_TWI0	BFIN_IRQ(45)	/* TWI0 Interrupt */
#define IRQ_TWI1	BFIN_IRQ(46)	/* TWI1 Interrupt */
#define IRQ_CAN0_RX	BFIN_IRQ(47)	/* CAN0 Receive Interrupt */
#define IRQ_CAN0_TX	BFIN_IRQ(48)	/* CAN0 Transmit Interrupt */
#define IRQ_MDMAS2	BFIN_IRQ(49)	/* MDMA Stream 2 Interrupt */
#define IRQ_MDMAS3	BFIN_IRQ(50)	/* MDMA Stream 3 Interrupt */
#define IRQ_MXVR_ERR	BFIN_IRQ(51)	/* MXVR Status (Error) Interrupt */
#define IRQ_MXVR_MSG	BFIN_IRQ(52)	/* MXVR Message Interrupt */
#define IRQ_MXVR_PKT	BFIN_IRQ(53)	/* MXVR Packet Interrupt */
#define IRQ_EPP1_ERR	BFIN_IRQ(54)	/* EPPI1 Error Interrupt */
#define IRQ_EPP2_ERR	BFIN_IRQ(55)	/* EPPI2 Error Interrupt */
#define IRQ_UART3_ERR	BFIN_IRQ(56)	/* UART3 Status (Error) Interrupt */
#define IRQ_HOST_ERR	BFIN_IRQ(57)	/* HOST Status (Error) Interrupt */
#define IRQ_PIXC_ERR	BFIN_IRQ(59)	/* PIXC Status (Error) Interrupt */
#define IRQ_NFC_ERR	BFIN_IRQ(60)	/* NFC Error Interrupt */
#define IRQ_ATAPI_ERR	BFIN_IRQ(61)	/* ATAPI Error Interrupt */
#define IRQ_CAN1_ERR	BFIN_IRQ(62)	/* CAN1 Status (Error) Interrupt */
#define IRQ_HS_DMA_ERR	BFIN_IRQ(63)	/* Handshake DMA Status Interrupt */
#define IRQ_PIXC_IN0	BFIN_IRQ(64)	/* PIXC IN0 (DMA15) Interrupt */
#define IRQ_PIXC_IN1	BFIN_IRQ(65)	/* PIXC IN1 (DMA16) Interrupt */
#define IRQ_PIXC_OUT	BFIN_IRQ(66)	/* PIXC OUT (DMA17) Interrupt */
#define IRQ_SDH		BFIN_IRQ(67)	/* SDH/NFC (DMA22) Interrupt */
#define IRQ_CNT		BFIN_IRQ(68)	/* CNT Interrupt */
#define IRQ_KEY		BFIN_IRQ(69)	/* KEY Interrupt */
#define IRQ_CAN1_RX	BFIN_IRQ(70)	/* CAN1 RX Interrupt */
#define IRQ_CAN1_TX	BFIN_IRQ(71)	/* CAN1 TX Interrupt */
#define IRQ_SDH_MASK0	BFIN_IRQ(72)	/* SDH Mask 0 Interrupt */
#define IRQ_SDH_MASK1	BFIN_IRQ(73)	/* SDH Mask 1 Interrupt */
#define IRQ_USB_INT0	BFIN_IRQ(75)	/* USB INT0 Interrupt */
#define IRQ_USB_INT1	BFIN_IRQ(76)	/* USB INT1 Interrupt */
#define IRQ_USB_INT2	BFIN_IRQ(77)	/* USB INT2 Interrupt */
#define IRQ_USB_DMA	BFIN_IRQ(78)	/* USB DMA Interrupt */
#define IRQ_OPTSEC	BFIN_IRQ(79)	/* OTPSEC Interrupt */
#define IRQ_TMR0	BFIN_IRQ(86)	/* Timer 0 Interrupt */
#define IRQ_TMR1	BFIN_IRQ(87)	/* Timer 1 Interrupt */
#define IRQ_TMR2	BFIN_IRQ(88)	/* Timer 2 Interrupt */
#define IRQ_TMR3	BFIN_IRQ(89)	/* Timer 3 Interrupt */
#define IRQ_TMR4	BFIN_IRQ(90)	/* Timer 4 Interrupt */
#define IRQ_TMR5	BFIN_IRQ(91)	/* Timer 5 Interrupt */
#define IRQ_TMR6	BFIN_IRQ(92)	/* Timer 6 Interrupt */
#define IRQ_TMR7	BFIN_IRQ(93)	/* Timer 7 Interrupt */
#define IRQ_PINT2	BFIN_IRQ(94)	/* PINT2 Interrupt */
#define IRQ_PINT3	BFIN_IRQ(95)	/* PINT3 Interrupt */

#define SYS_IRQS        IRQ_PINT3

#define BFIN_PA_IRQ(x)	((x) + SYS_IRQS + 1)
#define IRQ_PA0		BFIN_PA_IRQ(0)
#define IRQ_PA1		BFIN_PA_IRQ(1)
#define IRQ_PA2		BFIN_PA_IRQ(2)
#define IRQ_PA3		BFIN_PA_IRQ(3)
#define IRQ_PA4		BFIN_PA_IRQ(4)
#define IRQ_PA5		BFIN_PA_IRQ(5)
#define IRQ_PA6		BFIN_PA_IRQ(6)
#define IRQ_PA7		BFIN_PA_IRQ(7)
#define IRQ_PA8		BFIN_PA_IRQ(8)
#define IRQ_PA9		BFIN_PA_IRQ(9)
#define IRQ_PA10	BFIN_PA_IRQ(10)
#define IRQ_PA11	BFIN_PA_IRQ(11)
#define IRQ_PA12	BFIN_PA_IRQ(12)
#define IRQ_PA13	BFIN_PA_IRQ(13)
#define IRQ_PA14	BFIN_PA_IRQ(14)
#define IRQ_PA15	BFIN_PA_IRQ(15)

#define BFIN_PB_IRQ(x)	((x) + IRQ_PA15 + 1)
#define IRQ_PB0		BFIN_PB_IRQ(0)
#define IRQ_PB1		BFIN_PB_IRQ(1)
#define IRQ_PB2		BFIN_PB_IRQ(2)
#define IRQ_PB3		BFIN_PB_IRQ(3)
#define IRQ_PB4		BFIN_PB_IRQ(4)
#define IRQ_PB5		BFIN_PB_IRQ(5)
#define IRQ_PB6		BFIN_PB_IRQ(6)
#define IRQ_PB7		BFIN_PB_IRQ(7)
#define IRQ_PB8		BFIN_PB_IRQ(8)
#define IRQ_PB9		BFIN_PB_IRQ(9)
#define IRQ_PB10	BFIN_PB_IRQ(10)
#define IRQ_PB11	BFIN_PB_IRQ(11)
#define IRQ_PB12	BFIN_PB_IRQ(12)
#define IRQ_PB13	BFIN_PB_IRQ(13)
#define IRQ_PB14	BFIN_PB_IRQ(14)
#define IRQ_PB15	BFIN_PB_IRQ(15)

#define BFIN_PC_IRQ(x)	((x) + IRQ_PB15 + 1)
#define IRQ_PC0		BFIN_PC_IRQ(0)
#define IRQ_PC1		BFIN_PC_IRQ(1)
#define IRQ_PC2		BFIN_PC_IRQ(2)
#define IRQ_PC3		BFIN_PC_IRQ(3)
#define IRQ_PC4		BFIN_PC_IRQ(4)
#define IRQ_PC5		BFIN_PC_IRQ(5)
#define IRQ_PC6		BFIN_PC_IRQ(6)
#define IRQ_PC7		BFIN_PC_IRQ(7)
#define IRQ_PC8		BFIN_PC_IRQ(8)
#define IRQ_PC9		BFIN_PC_IRQ(9)
#define IRQ_PC10	BFIN_PC_IRQ(10)
#define IRQ_PC11	BFIN_PC_IRQ(11)
#define IRQ_PC12	BFIN_PC_IRQ(12)
#define IRQ_PC13	BFIN_PC_IRQ(13)
#define IRQ_PC14	BFIN_PC_IRQ(14)
#define IRQ_PC15	BFIN_PC_IRQ(15)

#define BFIN_PD_IRQ(x)	((x) + IRQ_PC15 + 1)
#define IRQ_PD0		BFIN_PD_IRQ(0)
#define IRQ_PD1		BFIN_PD_IRQ(1)
#define IRQ_PD2		BFIN_PD_IRQ(2)
#define IRQ_PD3		BFIN_PD_IRQ(3)
#define IRQ_PD4		BFIN_PD_IRQ(4)
#define IRQ_PD5		BFIN_PD_IRQ(5)
#define IRQ_PD6		BFIN_PD_IRQ(6)
#define IRQ_PD7		BFIN_PD_IRQ(7)
#define IRQ_PD8		BFIN_PD_IRQ(8)
#define IRQ_PD9		BFIN_PD_IRQ(9)
#define IRQ_PD10	BFIN_PD_IRQ(10)
#define IRQ_PD11	BFIN_PD_IRQ(11)
#define IRQ_PD12	BFIN_PD_IRQ(12)
#define IRQ_PD13	BFIN_PD_IRQ(13)
#define IRQ_PD14	BFIN_PD_IRQ(14)
#define IRQ_PD15	BFIN_PD_IRQ(15)

#define BFIN_PE_IRQ(x)	((x) + IRQ_PD15 + 1)
#define IRQ_PE0		BFIN_PE_IRQ(0)
#define IRQ_PE1		BFIN_PE_IRQ(1)
#define IRQ_PE2		BFIN_PE_IRQ(2)
#define IRQ_PE3		BFIN_PE_IRQ(3)
#define IRQ_PE4		BFIN_PE_IRQ(4)
#define IRQ_PE5		BFIN_PE_IRQ(5)
#define IRQ_PE6		BFIN_PE_IRQ(6)
#define IRQ_PE7		BFIN_PE_IRQ(7)
#define IRQ_PE8		BFIN_PE_IRQ(8)
#define IRQ_PE9		BFIN_PE_IRQ(9)
#define IRQ_PE10	BFIN_PE_IRQ(10)
#define IRQ_PE11	BFIN_PE_IRQ(11)
#define IRQ_PE12	BFIN_PE_IRQ(12)
#define IRQ_PE13	BFIN_PE_IRQ(13)
#define IRQ_PE14	BFIN_PE_IRQ(14)
#define IRQ_PE15	BFIN_PE_IRQ(15)


#ifdef CONFIG_IRQCHIP_DEMUX_GPIO
#define NR_IRQS     (IRQ_PH15+1)
#else
#define NR_IRQS     (IRQ_UART1_ERROR+1)
#endif

#define IVG7            7
#define IVG8            8
#define IVG9            9
#define IVG10           10
#define IVG11           11
#define IVG12           12
#define IVG13           13
#define IVG14           14
#define IVG15           15

/* IAR0 BIT FIELDS*/
#define IRQ_PLL_WAKEUP_POS  0
#define IRQ_DMA_ERROR_POS   4
#define IRQ_ERROR_POS       8
#define IRQ_RTC_POS         12
#define IRQ_PPI_POS         16
#define IRQ_SPORT0_RX_POS   20
#define IRQ_SPORT0_TX_POS   24
#define IRQ_SPORT1_RX_POS   28

/* IAR1 BIT FIELDS*/
#define IRQ_SPORT1_TX_POS   0
#define IRQ_TWI_POS         4
#define IRQ_SPI_POS         8
#define IRQ_UART0_RX_POS    12
#define IRQ_UART0_TX_POS    16
#define IRQ_UART1_RX_POS    20
#define IRQ_UART1_TX_POS    24
#define IRQ_CAN_RX_POS      28

/* IAR2 BIT FIELDS*/
#define IRQ_CAN_TX_POS      0
#define IRQ_MAC_RX_POS      4
#define IRQ_MAC_TX_POS      8
#define IRQ_TMR0_POS        12
#define IRQ_TMR1_POS        16
#define IRQ_TMR2_POS        20
#define IRQ_TMR3_POS        24
#define IRQ_TMR4_POS        28

/* IAR3 BIT FIELDS*/
#define IRQ_TMR5_POS        0
#define IRQ_TMR6_POS        4
#define IRQ_TMR7_POS        8
#define IRQ_PROG_INTA_POS   12
#define IRQ_PORTG_INTB_POS   16
#define IRQ_MEM_DMA0_POS    20
#define IRQ_MEM_DMA1_POS    24
#define IRQ_WATCH_POS       28

#endif				/* _BF537_IRQ_H_ */
