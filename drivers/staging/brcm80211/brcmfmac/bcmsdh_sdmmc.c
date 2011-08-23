/*
 * Copyright (c) 2010 Broadcom Corporation
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/mmc/sdio.h>
#include <linux/mmc/core.h>
#include <linux/mmc/sdio_func.h>
#include <linux/mmc/sdio_ids.h>
#include <linux/mmc/card.h>
#include <linux/suspend.h>
#include <linux/errno.h>
#include <linux/sched.h>	/* request_irq() */
#include <net/cfg80211.h>

#include <defs.h>
#include <brcm_hw_ids.h>
#include <brcmu_utils.h>
#include <brcmu_wifi.h>
#include "sdio_host.h"
#include "dhd.h"
#include "dhd_dbg.h"
#include "wl_cfg80211.h"

#if !defined(SDIO_VENDOR_ID_BROADCOM)
#define SDIO_VENDOR_ID_BROADCOM		0x02d0
#endif				/* !defined(SDIO_VENDOR_ID_BROADCOM) */

#define DMA_ALIGN_MASK	0x03

#if !defined(SDIO_DEVICE_ID_BROADCOM_4329)
#define SDIO_DEVICE_ID_BROADCOM_4329	0x4329
#endif		/* !defined(SDIO_DEVICE_ID_BROADCOM_4329) */

static int brcmf_sdioh_get_cisaddr(struct brcmf_sdio_dev *sdiodev, u32 regaddr);
static int brcmf_ops_sdio_probe(struct sdio_func *func,
				const struct sdio_device_id *id);
static void brcmf_ops_sdio_remove(struct sdio_func *func);

#ifdef CONFIG_PM
static int brcmf_sdio_suspend(struct device *dev);
static int brcmf_sdio_resume(struct device *dev);
#endif /* CONFIG_PM */

uint sd_f2_blocksize = 512;	/* Default blocksize */

/* devices we support, null terminated */
static const struct sdio_device_id brcmf_sdmmc_ids[] = {
	{SDIO_DEVICE(SDIO_VENDOR_ID_BROADCOM, SDIO_DEVICE_ID_BROADCOM_4329)},
	{ /* end: all zeroes */ },
};

#ifdef CONFIG_PM_SLEEP
static const struct dev_pm_ops brcmf_sdio_pm_ops = {
	.suspend	= brcmf_sdio_suspend,
	.resume		= brcmf_sdio_resume,
};
#endif	/* CONFIG_PM_SLEEP */

static struct sdio_driver brcmf_sdmmc_driver = {
	.probe = brcmf_ops_sdio_probe,
	.remove = brcmf_ops_sdio_remove,
	.name = "brcmfmac",
	.id_table = brcmf_sdmmc_ids,
#ifdef CONFIG_PM_SLEEP
	.drv = {
		.pm = &brcmf_sdio_pm_ops,
	},
#endif	/* CONFIG_PM_SLEEP */
};

MODULE_DEVICE_TABLE(sdio, brcmf_sdmmc_ids);

#ifdef CONFIG_PM_SLEEP
DECLARE_WAIT_QUEUE_HEAD(sdioh_request_byte_wait);
DECLARE_WAIT_QUEUE_HEAD(sdioh_request_word_wait);
DECLARE_WAIT_QUEUE_HEAD(sdioh_request_packet_wait);
DECLARE_WAIT_QUEUE_HEAD(sdioh_request_buffer_wait);
#define BRCMF_PM_RESUME_WAIT(a, b) do { \
		int retry = 0; \
		while (atomic_read(&b->suspend) && retry++ != 30) { \
			wait_event_timeout(a, false, HZ/100); \
		} \
	}	while (0)
#define BRCMF_PM_RESUME_RETURN_ERROR(a, b)	\
	do { if (atomic_read(&b->suspend)) return a; } while (0)
#else
#define BRCMF_PM_RESUME_WAIT(a, b)
#define BRCMF_PM_RESUME_RETURN_ERROR(a, b)
#endif		/* CONFIG_PM_SLEEP */

static int
brcmf_sdioh_card_regread(struct brcmf_sdio_dev *sdiodev, int func, u32 regaddr,
			 int regsize, u32 *data);

static int brcmf_sdioh_enablefuncs(struct brcmf_sdio_dev *sdiodev)
{
	int err_ret;
	u32 fbraddr;
	u8 func;

	BRCMF_TRACE(("%s\n", __func__));

	/* Get the Card's common CIS address */
	sdiodev->func_cis_ptr[0] = brcmf_sdioh_get_cisaddr(sdiodev,
							   SDIO_CCCR_CIS);
	BRCMF_INFO(("%s: Card's Common CIS Ptr = 0x%x\n", __func__,
		 sdiodev->func_cis_ptr[0]));

	/* Get the Card's function CIS (for each function) */
	for (fbraddr = SDIO_FBR_BASE(1), func = 1;
	     func <= sdiodev->num_funcs; func++, fbraddr += SDIOD_FBR_SIZE) {
		sdiodev->func_cis_ptr[func] =
		    brcmf_sdioh_get_cisaddr(sdiodev, SDIO_FBR_CIS + fbraddr);
		BRCMF_INFO(("%s: Function %d CIS Ptr = 0x%x\n", __func__, func,
			 sdiodev->func_cis_ptr[func]));
	}

	/* Enable Function 1 */
	sdio_claim_host(sdiodev->func[1]);
	err_ret = sdio_enable_func(sdiodev->func[1]);
	sdio_release_host(sdiodev->func[1]);
	if (err_ret)
		BRCMF_ERROR(("brcmf_sdioh_enablefuncs: Failed to enable F1 "
			"Err: 0x%08x\n", err_ret));

	return false;
}

/*
 *	Public entry points & extern's
 */
int brcmf_sdioh_attach(struct brcmf_sdio_dev *sdiodev)
{
	int err_ret = 0;

	BRCMF_TRACE(("%s\n", __func__));

	sdiodev->num_funcs = 2;

	sdio_claim_host(sdiodev->func[1]);
	err_ret = sdio_set_block_size(sdiodev->func[1], 64);
	sdio_release_host(sdiodev->func[1]);
	if (err_ret) {
		BRCMF_ERROR(("%s: Failed to set F1 blocksize\n", __func__));
		goto out;
	}

	sdio_claim_host(sdiodev->func[2]);
	err_ret = sdio_set_block_size(sdiodev->func[2], sd_f2_blocksize);
	sdio_release_host(sdiodev->func[2]);
	if (err_ret) {
		BRCMF_ERROR(("%s: Failed to set F2 blocksize"
			" to %d\n", __func__, sd_f2_blocksize));
		goto out;
	}

	brcmf_sdioh_enablefuncs(sdiodev);

out:
	BRCMF_TRACE(("%s: Done\n", __func__));
	return err_ret;
}

void brcmf_sdioh_detach(struct brcmf_sdio_dev *sdiodev)
{
	BRCMF_TRACE(("%s\n", __func__));

	/* Disable Function 2 */
	sdio_claim_host(sdiodev->func[2]);
	sdio_disable_func(sdiodev->func[2]);
	sdio_release_host(sdiodev->func[2]);

	/* Disable Function 1 */
	sdio_claim_host(sdiodev->func[1]);
	sdio_disable_func(sdiodev->func[1]);
	sdio_release_host(sdiodev->func[1]);

}

static int brcmf_sdioh_get_cisaddr(struct brcmf_sdio_dev *sdiodev, u32 regaddr)
{
	/* read 24 bits and return valid 17 bit addr */
	int i;
	u32 scratch, regdata;
	u8 *ptr = (u8 *)&scratch;
	for (i = 0; i < 3; i++) {
		if ((brcmf_sdioh_card_regread(sdiodev, 0, regaddr, 1,
				&regdata)) != SUCCESS)
			BRCMF_ERROR(("%s: Can't read!\n", __func__));

		*ptr++ = (u8) regdata;
		regaddr++;
	}

	/* Only the lower 17-bits are valid */
	scratch = le32_to_cpu(scratch);
	scratch &= 0x0001FFFF;
	return scratch;
}

extern int
brcmf_sdioh_cis_read(struct brcmf_sdio_dev *sdiodev, uint func,
		     u8 *cisd, u32 length)
{
	u32 count;
	int offset;
	u32 foo;
	u8 *cis = cisd;

	BRCMF_TRACE(("%s: Func = %d\n", __func__, func));

	if (!sdiodev->func_cis_ptr[func]) {
		memset(cis, 0, length);
		BRCMF_ERROR(("%s: no func_cis_ptr[%d]\n", __func__, func));
		return -ENOTSUPP;
	}

	BRCMF_ERROR(("%s: func_cis_ptr[%d]=0x%04x\n", __func__, func,
		sdiodev->func_cis_ptr[func]));

	for (count = 0; count < length; count++) {
		offset = sdiodev->func_cis_ptr[func] + count;
		if (brcmf_sdioh_card_regread(sdiodev, 0, offset, 1, &foo) < 0) {
			BRCMF_ERROR(("%s: regread failed: Can't read CIS\n",
				__func__));
			return -EIO;
		}

		*cis = (u8) (foo & 0xff);
		cis++;
	}

	return 0;
}

extern int
brcmf_sdioh_request_byte(struct brcmf_sdio_dev *sdiodev, uint rw, uint func,
			 uint regaddr, u8 *byte)
{
	int err_ret;

	BRCMF_INFO(("%s: rw=%d, func=%d, addr=0x%05x\n", __func__, rw, func,
		 regaddr));

	BRCMF_PM_RESUME_WAIT(sdioh_request_byte_wait, sdiodev);
	BRCMF_PM_RESUME_RETURN_ERROR(-EIO, sdiodev);
	if (rw) {		/* CMD52 Write */
		if (func == 0) {
			/* Can only directly write to some F0 registers.
			 * Handle F2 enable
			 * as a special case.
			 */
			if (regaddr == SDIO_CCCR_IOEx) {
				if (sdiodev->func[2]) {
					sdio_claim_host(sdiodev->func[2]);
					if (*byte & SDIO_FUNC_ENABLE_2) {
						/* Enable Function 2 */
						err_ret =
						    sdio_enable_func
						    (sdiodev->func[2]);
						if (err_ret)
							BRCMF_ERROR((
								"request_byte: "
								"enable F2 "
								"failed:%d\n",
								 err_ret));
					} else {
						/* Disable Function 2 */
						err_ret =
						    sdio_disable_func
						    (sdiodev->func[2]);
						if (err_ret)
							BRCMF_ERROR((
								"request_byte: "
								"Disab F2 "
								"failed:%d\n",
								 err_ret));
					}
					sdio_release_host(sdiodev->func[2]);
				}
			}
			/* to allow abort command through F1 */
			else if (regaddr == SDIO_CCCR_ABORT) {
				sdio_claim_host(sdiodev->func[func]);
				/*
				 * this sdio_f0_writeb() can be replaced
				 * with another api
				 * depending upon MMC driver change.
				 * As of this time, this is temporaray one
				 */
				sdio_writeb(sdiodev->func[func], *byte,
					    regaddr, &err_ret);
				sdio_release_host(sdiodev->func[func]);
			} else if (regaddr < 0xF0) {
				BRCMF_ERROR(("brcmf: F0 Wr:0x%02x: write "
					"disallowed\n", regaddr));
			} else {
				/* Claim host controller, perform F0 write,
				 and release */
				sdio_claim_host(sdiodev->func[func]);
				sdio_f0_writeb(sdiodev->func[func], *byte,
					       regaddr, &err_ret);
				sdio_release_host(sdiodev->func[func]);
			}
		} else {
			/* Claim host controller, perform Fn write,
			 and release */
			sdio_claim_host(sdiodev->func[func]);
			sdio_writeb(sdiodev->func[func], *byte, regaddr,
				    &err_ret);
			sdio_release_host(sdiodev->func[func]);
		}
	} else {		/* CMD52 Read */
		/* Claim host controller, perform Fn read, and release */
		sdio_claim_host(sdiodev->func[func]);

		if (func == 0) {
			*byte =
			    sdio_f0_readb(sdiodev->func[func], regaddr,
					  &err_ret);
		} else {
			*byte =
			    sdio_readb(sdiodev->func[func], regaddr,
				       &err_ret);
		}

		sdio_release_host(sdiodev->func[func]);
	}

	if (err_ret)
		BRCMF_ERROR(("brcmf: Failed to %s byte F%d:@0x%05x=%02x, "
			"Err: %d\n", rw ? "Write" : "Read", func, regaddr,
			*byte, err_ret));

	return err_ret;
}

extern int
brcmf_sdioh_request_word(struct brcmf_sdio_dev *sdiodev, uint cmd_type, uint rw,
			 uint func, uint addr, u32 *word, uint nbytes)
{
	int err_ret = -EIO;

	if (func == 0) {
		BRCMF_ERROR(("%s: Only CMD52 allowed to F0.\n", __func__));
		return -EINVAL;
	}

	BRCMF_INFO(("%s: cmd_type=%d, rw=%d, func=%d, addr=0x%05x, nbytes=%d\n",
		 __func__, cmd_type, rw, func, addr, nbytes));

	BRCMF_PM_RESUME_WAIT(sdioh_request_word_wait, sdiodev);
	BRCMF_PM_RESUME_RETURN_ERROR(-EIO, sdiodev);
	/* Claim host controller */
	sdio_claim_host(sdiodev->func[func]);

	if (rw) {		/* CMD52 Write */
		if (nbytes == 4)
			sdio_writel(sdiodev->func[func], *word, addr,
				    &err_ret);
		else if (nbytes == 2)
			sdio_writew(sdiodev->func[func], (*word & 0xFFFF),
				    addr, &err_ret);
		else
			BRCMF_ERROR(("%s: Invalid nbytes: %d\n",
				     __func__, nbytes));
	} else {		/* CMD52 Read */
		if (nbytes == 4)
			*word =
			    sdio_readl(sdiodev->func[func], addr, &err_ret);
		else if (nbytes == 2)
			*word =
			    sdio_readw(sdiodev->func[func], addr,
				       &err_ret) & 0xFFFF;
		else
			BRCMF_ERROR(("%s: Invalid nbytes: %d\n",
				     __func__, nbytes));
	}

	/* Release host controller */
	sdio_release_host(sdiodev->func[func]);

	if (err_ret)
		BRCMF_ERROR(("brcmf: Failed to %s word, Err: 0x%08x\n",
			rw ? "Write" : "Read", err_ret));

	return err_ret;
}

static int
brcmf_sdioh_request_packet(struct brcmf_sdio_dev *sdiodev, uint fix_inc,
			   uint write, uint func, uint addr,
			   struct sk_buff *pkt)
{
	bool fifo = (fix_inc == SDIOH_DATA_FIX);
	u32 SGCount = 0;
	int err_ret = 0;

	struct sk_buff *pnext;

	BRCMF_TRACE(("%s: Enter\n", __func__));

	BRCMF_PM_RESUME_WAIT(sdioh_request_packet_wait, sdiodev);
	BRCMF_PM_RESUME_RETURN_ERROR(-EIO, sdiodev);

	/* Claim host controller */
	sdio_claim_host(sdiodev->func[func]);
	for (pnext = pkt; pnext; pnext = pnext->next) {
		uint pkt_len = pnext->len;
		pkt_len += 3;
		pkt_len &= 0xFFFFFFFC;

		if ((write) && (!fifo)) {
			err_ret = sdio_memcpy_toio(sdiodev->func[func], addr,
						   ((u8 *) (pnext->data)),
						   pkt_len);
		} else if (write) {
			err_ret = sdio_memcpy_toio(sdiodev->func[func], addr,
						   ((u8 *) (pnext->data)),
						   pkt_len);
		} else if (fifo) {
			err_ret = sdio_readsb(sdiodev->func[func],
					      ((u8 *) (pnext->data)),
					      addr, pkt_len);
		} else {
			err_ret = sdio_memcpy_fromio(sdiodev->func[func],
						     ((u8 *) (pnext->data)),
						     addr, pkt_len);
		}

		if (err_ret) {
			BRCMF_ERROR(("%s: %s FAILED %p[%d], addr=0x%05x, "
				 "pkt_len=%d, ERR=0x%08x\n", __func__,
				 (write) ? "TX" : "RX",
				 pnext, SGCount, addr, pkt_len, err_ret));
		} else {
			BRCMF_TRACE(("%s: %s xfr'd %p[%d], addr=0x%05x, "
				     "len=%d\n", __func__,
				     (write) ? "TX" : "RX",
				     pnext, SGCount, addr, pkt_len));
		}

		if (!fifo)
			addr += pkt_len;
		SGCount++;

	}

	/* Release host controller */
	sdio_release_host(sdiodev->func[func]);

	BRCMF_TRACE(("%s: Exit\n", __func__));
	return err_ret;
}

/*
 * This function takes a buffer or packet, and fixes everything up
 * so that in the end, a DMA-able packet is created.
 *
 * A buffer does not have an associated packet pointer,
 * and may or may not be aligned.
 * A packet may consist of a single packet, or a packet chain.
 * If it is a packet chain, then all the packets in the chain
 * must be properly aligned.
 *
 * If the packet data is not aligned, then there may only be
 * one packet, and in this case,  it is copied to a new
 * aligned packet.
 *
 */
extern int
brcmf_sdioh_request_buffer(struct brcmf_sdio_dev *sdiodev, uint pio_dma,
			   uint fix_inc, uint write, uint func, uint addr,
			   uint reg_width, uint buflen_u, u8 *buffer,
			   struct sk_buff *pkt)
{
	int Status;
	struct sk_buff *mypkt = NULL;

	BRCMF_TRACE(("%s: Enter\n", __func__));

	BRCMF_PM_RESUME_WAIT(sdioh_request_buffer_wait, sdiodev);
	BRCMF_PM_RESUME_RETURN_ERROR(-EIO, sdiodev);
	/* Case 1: we don't have a packet. */
	if (pkt == NULL) {
		BRCMF_DATA(("%s: Creating new %s Packet, len=%d\n",
			 __func__, write ? "TX" : "RX", buflen_u));
		mypkt = brcmu_pkt_buf_get_skb(buflen_u);
		if (!mypkt) {
			BRCMF_ERROR(("%s: brcmu_pkt_buf_get_skb failed: "
				     "len %d\n", __func__, buflen_u));
			return -EIO;
		}

		/* For a write, copy the buffer data into the packet. */
		if (write)
			memcpy(mypkt->data, buffer, buflen_u);

		Status = brcmf_sdioh_request_packet(sdiodev, fix_inc, write,
						    func, addr, mypkt);

		/* For a read, copy the packet data back to the buffer. */
		if (!write)
			memcpy(buffer, mypkt->data, buflen_u);

		brcmu_pkt_buf_free_skb(mypkt);
	} else if (((ulong) (pkt->data) & DMA_ALIGN_MASK) != 0) {
		/*
		 * Case 2: We have a packet, but it is unaligned.
		 * In this case, we cannot have a chain (pkt->next == NULL)
		 */
		BRCMF_DATA(("%s: Creating aligned %s Packet, len=%d\n",
			 __func__, write ? "TX" : "RX", pkt->len));
		mypkt = brcmu_pkt_buf_get_skb(pkt->len);
		if (!mypkt) {
			BRCMF_ERROR(("%s: brcmu_pkt_buf_get_skb failed: "
				     "len %d\n", __func__, pkt->len));
			return -EIO;
		}

		/* For a write, copy the buffer data into the packet. */
		if (write)
			memcpy(mypkt->data, pkt->data, pkt->len);

		Status = brcmf_sdioh_request_packet(sdiodev, fix_inc, write,
						    func, addr, mypkt);

		/* For a read, copy the packet data back to the buffer. */
		if (!write)
			memcpy(pkt->data, mypkt->data, mypkt->len);

		brcmu_pkt_buf_free_skb(mypkt);
	} else {		/* case 3: We have a packet and
				 it is aligned. */
		BRCMF_DATA(("%s: Aligned %s Packet, direct DMA\n",
			 __func__, write ? "Tx" : "Rx"));
		Status = brcmf_sdioh_request_packet(sdiodev, fix_inc, write,
						    func, addr, pkt);
	}

	return Status;
}

/* Read client card reg */
int
brcmf_sdioh_card_regread(struct brcmf_sdio_dev *sdiodev, int func, u32 regaddr,
			 int regsize, u32 *data)
{

	if ((func == 0) || (regsize == 1)) {
		u8 temp = 0;

		brcmf_sdioh_request_byte(sdiodev, SDIOH_READ, func, regaddr,
					 &temp);
		*data = temp;
		*data &= 0xff;
		BRCMF_DATA(("%s: byte read data=0x%02x\n", __func__, *data));
	} else {
		brcmf_sdioh_request_word(sdiodev, 0, SDIOH_READ, func, regaddr,
					 data, regsize);
		if (regsize == 2)
			*data &= 0xffff;

		BRCMF_DATA(("%s: word read data=0x%08x\n", __func__, *data));
	}

	return SUCCESS;
}

static int brcmf_ops_sdio_probe(struct sdio_func *func,
			      const struct sdio_device_id *id)
{
	int ret = 0;
	struct brcmf_sdio_dev *sdiodev;
	BRCMF_TRACE(("sdio_probe: %s Enter\n", __func__));
	BRCMF_TRACE(("sdio_probe: func->class=%x\n", func->class));
	BRCMF_TRACE(("sdio_vendor: 0x%04x\n", func->vendor));
	BRCMF_TRACE(("sdio_device: 0x%04x\n", func->device));
	BRCMF_TRACE(("Function#: 0x%04x\n", func->num));

	if (func->num == 1) {
		if (dev_get_drvdata(&func->card->dev)) {
			BRCMF_ERROR(("%s: card private drvdata occupied.\n",
				     __func__));
			return -ENXIO;
		}
		sdiodev = kzalloc(sizeof(struct brcmf_sdio_dev), GFP_KERNEL);
		if (!sdiodev)
			return -ENOMEM;
		sdiodev->func[0] = func->card->sdio_func[0];
		sdiodev->func[1] = func;
		dev_set_drvdata(&func->card->dev, sdiodev);

		atomic_set(&sdiodev->suspend, false);
	}

	if (func->num == 2) {
		sdiodev = dev_get_drvdata(&func->card->dev);
		if ((!sdiodev) || (sdiodev->func[1]->card != func->card))
			return -ENODEV;
		sdiodev->func[2] = func;

		brcmf_cfg80211_sdio_func(func);
		BRCMF_TRACE(("F2 found, calling brcmf_sdio_probe...\n"));
		ret = brcmf_sdio_probe(sdiodev);
	}

	return ret;
}

static void brcmf_ops_sdio_remove(struct sdio_func *func)
{
	struct brcmf_sdio_dev *sdiodev;
	BRCMF_TRACE(("%s Enter\n", __func__));
	BRCMF_INFO(("func->class=%x\n", func->class));
	BRCMF_INFO(("sdio_vendor: 0x%04x\n", func->vendor));
	BRCMF_INFO(("sdio_device: 0x%04x\n", func->device));
	BRCMF_INFO(("Function#: 0x%04x\n", func->num));

	if (func->num == 2) {
		sdiodev = dev_get_drvdata(&func->card->dev);
		BRCMF_TRACE(("F2 found, calling brcmf_sdio_remove...\n"));
		brcmf_sdio_remove(sdiodev);
		dev_set_drvdata(&func->card->dev, NULL);
		kfree(sdiodev);
	}
}


#ifdef CONFIG_PM_SLEEP
static int brcmf_sdio_suspend(struct device *dev)
{
	mmc_pm_flag_t sdio_flags;
	struct brcmf_sdio_dev *sdiodev;
	struct sdio_func *func = dev_to_sdio_func(dev);
	int ret = 0;

	BRCMF_TRACE(("%s\n", __func__));

	sdiodev = dev_get_drvdata(&func->card->dev);

	atomic_set(&sdiodev->suspend, true);

	sdio_flags = sdio_get_host_pm_caps(sdiodev->func[1]);
	if (!(sdio_flags & MMC_PM_KEEP_POWER)) {
		BRCMF_ERROR(("Host can't keep power while suspended\n"));
		return -EINVAL;
	}

	ret = sdio_set_host_pm_flags(sdiodev->func[1], MMC_PM_KEEP_POWER);
	if (ret) {
		BRCMF_ERROR(("Failed to set pm_flags\n"));
		return ret;
	}

	brcmf_sdio_wdtmr_enable(sdiodev, false);

	return ret;
}

static int brcmf_sdio_resume(struct device *dev)
{
	struct brcmf_sdio_dev *sdiodev;
	struct sdio_func *func = dev_to_sdio_func(dev);

	sdiodev = dev_get_drvdata(&func->card->dev);
	brcmf_sdio_wdtmr_enable(sdiodev, true);
	atomic_set(&sdiodev->suspend, false);
	return 0;
}
#endif		/* CONFIG_PM_SLEEP */

/*
 * module init
*/
int brcmf_sdio_function_init(void)
{
	int error = 0;
	BRCMF_TRACE(("brcmf_sdio_function_init: %s Enter\n", __func__));

	error = sdio_register_driver(&brcmf_sdmmc_driver);

	return error;
}

/*
 * module cleanup
*/
void brcmf_sdio_function_cleanup(void)
{
	BRCMF_TRACE(("%s Enter\n", __func__));

	sdio_unregister_driver(&brcmf_sdmmc_driver);
}
