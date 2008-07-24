/*
 * Frame buffer driver for Trident Blade and Image series
 *
 * Copyright 2001, 2002 - Jani Monoses   <jani@iv.ro>
 *
 *
 * CREDITS:(in order of appearance)
 *	skeletonfb.c by Geert Uytterhoeven and other fb code in drivers/video
 *	Special thanks ;) to Mattia Crivellini <tia@mclink.it>
 *	much inspired by the XFree86 4.x Trident driver sources
 *	by Alan Hourihane the FreeVGA project
 *	Francesco Salvestrini <salvestrini@users.sf.net> XP support,
 *	code, suggestions
 * TODO:
 *	timing value tweaking so it looks good on every monitor in every mode
 *	TGUI acceleration
 */

#include <linux/module.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/pci.h>

#include <linux/delay.h>
#include <video/vga.h>
#include <video/trident.h>

#define VERSION		"0.7.9-NEWAPI"

struct tridentfb_par {
	void __iomem *io_virt;	/* iospace virtual memory address */
	u32 pseudo_pal[16];
	int chip_id;
	int flatpanel;
	void (*init_accel) (struct tridentfb_par *, int, int);
	void (*wait_engine) (struct tridentfb_par *);
	void (*fill_rect)
		(struct tridentfb_par *par, u32, u32, u32, u32, u32, u32);
	void (*copy_rect)
		(struct tridentfb_par *par, u32, u32, u32, u32, u32, u32);
};

static unsigned char eng_oper;	/* engine operation... */
static struct fb_ops tridentfb_ops;

static struct fb_fix_screeninfo tridentfb_fix = {
	.id = "Trident",
	.type = FB_TYPE_PACKED_PIXELS,
	.ypanstep = 1,
	.visual = FB_VISUAL_PSEUDOCOLOR,
	.accel = FB_ACCEL_NONE,
};

/* defaults which are normally overriden by user values */

/* video mode */
static char *mode_option __devinitdata = "640x480";
static int bpp __devinitdata = 8;

static int noaccel __devinitdata;

static int center;
static int stretch;

static int fp __devinitdata;
static int crt __devinitdata;

static int memsize __devinitdata;
static int memdiff __devinitdata;
static int nativex;

module_param(mode_option, charp, 0);
MODULE_PARM_DESC(mode_option, "Initial video mode e.g. '648x480-8@60'");
module_param_named(mode, mode_option, charp, 0);
MODULE_PARM_DESC(mode, "Initial video mode e.g. '648x480-8@60' (deprecated)");
module_param(bpp, int, 0);
module_param(center, int, 0);
module_param(stretch, int, 0);
module_param(noaccel, int, 0);
module_param(memsize, int, 0);
module_param(memdiff, int, 0);
module_param(nativex, int, 0);
module_param(fp, int, 0);
MODULE_PARM_DESC(fp, "Define if flatpanel is connected");
module_param(crt, int, 0);
MODULE_PARM_DESC(crt, "Define if CRT is connected");

static int is_oldclock(int id)
{
	return (id == TGUI9660);
}

static int is_blade(int id)
{
	return	(id == BLADE3D) ||
		(id == CYBERBLADEE4) ||
		(id == CYBERBLADEi7) ||
		(id == CYBERBLADEi7D) ||
		(id == CYBERBLADEi1) ||
		(id == CYBERBLADEi1D) ||
		(id == CYBERBLADEAi1) ||
		(id == CYBERBLADEAi1D);
}

static int is_xp(int id)
{
	return	(id == CYBERBLADEXPAi1) ||
		(id == CYBERBLADEXPm8) ||
		(id == CYBERBLADEXPm16);
}

static int is3Dchip(int id)
{
	return ((id == BLADE3D) || (id == CYBERBLADEE4) ||
		(id == CYBERBLADEi7) || (id == CYBERBLADEi7D) ||
		(id == CYBER9397) || (id == CYBER9397DVD) ||
		(id == CYBER9520) || (id == CYBER9525DVD) ||
		(id == IMAGE975) || (id == IMAGE985) ||
		(id == CYBERBLADEi1) || (id == CYBERBLADEi1D) ||
		(id == CYBERBLADEAi1) || (id == CYBERBLADEAi1D) ||
		(id == CYBERBLADEXPm8) || (id == CYBERBLADEXPm16) ||
		(id == CYBERBLADEXPAi1));
}

static int iscyber(int id)
{
	switch (id) {
	case CYBER9388:
	case CYBER9382:
	case CYBER9385:
	case CYBER9397:
	case CYBER9397DVD:
	case CYBER9520:
	case CYBER9525DVD:
	case CYBERBLADEE4:
	case CYBERBLADEi7D:
	case CYBERBLADEi1:
	case CYBERBLADEi1D:
	case CYBERBLADEAi1:
	case CYBERBLADEAi1D:
	case CYBERBLADEXPAi1:
		return 1;

	case CYBER9320:
	case TGUI9660:
	case IMAGE975:
	case IMAGE985:
	case BLADE3D:
	case CYBERBLADEi7:	/* VIA MPV4 integrated version */

	default:
		/* case CYBERBLDAEXPm8:  Strange */
		/* case CYBERBLDAEXPm16: Strange */
		return 0;
	}
}

static inline void t_outb(struct tridentfb_par *p, u8 val, u16 reg)
{
	fb_writeb(val, p->io_virt + reg);
}

static inline u8 t_inb(struct tridentfb_par *p, u16 reg)
{
	return fb_readb(p->io_virt + reg);
}

static inline void writemmr(struct tridentfb_par *par, u16 r, u32 v)
{
	fb_writel(v, par->io_virt + r);
}

static inline u32 readmmr(struct tridentfb_par *par, u16 r)
{
	return fb_readl(par->io_virt + r);
}

/*
 * Blade specific acceleration.
 */

#define point(x, y) ((y) << 16 | (x))
#define STA	0x2120
#define CMD	0x2144
#define ROP	0x2148
#define CLR	0x2160
#define SR1	0x2100
#define SR2	0x2104
#define DR1	0x2108
#define DR2	0x210C

#define ROP_S	0xCC

static void blade_init_accel(struct tridentfb_par *par, int pitch, int bpp)
{
	int v1 = (pitch >> 3) << 20;
	int tmp = 0, v2;
	switch (bpp) {
	case 8:
		tmp = 0;
		break;
	case 15:
		tmp = 5;
		break;
	case 16:
		tmp = 1;
		break;
	case 24:
	case 32:
		tmp = 2;
		break;
	}
	v2 = v1 | (tmp << 29);
	writemmr(par, 0x21C0, v2);
	writemmr(par, 0x21C4, v2);
	writemmr(par, 0x21B8, v2);
	writemmr(par, 0x21BC, v2);
	writemmr(par, 0x21D0, v1);
	writemmr(par, 0x21D4, v1);
	writemmr(par, 0x21C8, v1);
	writemmr(par, 0x21CC, v1);
	writemmr(par, 0x216C, 0);
}

static void blade_wait_engine(struct tridentfb_par *par)
{
	while (readmmr(par, STA) & 0xFA800000) ;
}

static void blade_fill_rect(struct tridentfb_par *par,
			    u32 x, u32 y, u32 w, u32 h, u32 c, u32 rop)
{
	writemmr(par, CLR, c);
	writemmr(par, ROP, rop ? 0x66 : ROP_S);
	writemmr(par, CMD, 0x20000000 | 1 << 19 | 1 << 4 | 2 << 2);

	writemmr(par, DR1, point(x, y));
	writemmr(par, DR2, point(x + w - 1, y + h - 1));
}

static void blade_copy_rect(struct tridentfb_par *par,
			    u32 x1, u32 y1, u32 x2, u32 y2, u32 w, u32 h)
{
	u32 s1, s2, d1, d2;
	int direction = 2;
	s1 = point(x1, y1);
	s2 = point(x1 + w - 1, y1 + h - 1);
	d1 = point(x2, y2);
	d2 = point(x2 + w - 1, y2 + h - 1);

	if ((y1 > y2) || ((y1 == y2) && (x1 > x2)))
		direction = 0;

	writemmr(par, ROP, ROP_S);
	writemmr(par, CMD, 0xE0000000 | 1 << 19 | 1 << 4 | 1 << 2 | direction);

	writemmr(par, SR1, direction ? s2 : s1);
	writemmr(par, SR2, direction ? s1 : s2);
	writemmr(par, DR1, direction ? d2 : d1);
	writemmr(par, DR2, direction ? d1 : d2);
}

/*
 * BladeXP specific acceleration functions
 */

#define ROP_P 0xF0
#define masked_point(x, y) ((y & 0xffff)<<16|(x & 0xffff))

static void xp_init_accel(struct tridentfb_par *par, int pitch, int bpp)
{
	int tmp = 0, v1;
	unsigned char x = 0;

	switch (bpp) {
	case 8:
		x = 0;
		break;
	case 16:
		x = 1;
		break;
	case 24:
		x = 3;
		break;
	case 32:
		x = 2;
		break;
	}

	switch (pitch << (bpp >> 3)) {
	case 8192:
	case 512:
		x |= 0x00;
		break;
	case 1024:
		x |= 0x04;
		break;
	case 2048:
		x |= 0x08;
		break;
	case 4096:
		x |= 0x0C;
		break;
	}

	t_outb(par, x, 0x2125);

	eng_oper = x | 0x40;

	switch (bpp) {
	case 8:
		tmp = 18;
		break;
	case 15:
	case 16:
		tmp = 19;
		break;
	case 24:
	case 32:
		tmp = 20;
		break;
	}

	v1 = pitch << tmp;

	writemmr(par, 0x2154, v1);
	writemmr(par, 0x2150, v1);
	t_outb(par, 3, 0x2126);
}

static void xp_wait_engine(struct tridentfb_par *par)
{
	int busy;
	int count, timeout;

	count = 0;
	timeout = 0;
	for (;;) {
		busy = t_inb(par, STA) & 0x80;
		if (busy != 0x80)
			return;
		count++;
		if (count == 10000000) {
			/* Timeout */
			count = 9990000;
			timeout++;
			if (timeout == 8) {
				/* Reset engine */
				t_outb(par, 0x00, 0x2120);
				return;
			}
		}
	}
}

static void xp_fill_rect(struct tridentfb_par *par,
			 u32 x, u32 y, u32 w, u32 h, u32 c, u32 rop)
{
	writemmr(par, 0x2127, ROP_P);
	writemmr(par, 0x2158, c);
	writemmr(par, 0x2128, 0x4000);
	writemmr(par, 0x2140, masked_point(h, w));
	writemmr(par, 0x2138, masked_point(y, x));
	t_outb(par, 0x01, 0x2124);
	t_outb(par, eng_oper, 0x2125);
}

static void xp_copy_rect(struct tridentfb_par *par,
			 u32 x1, u32 y1, u32 x2, u32 y2, u32 w, u32 h)
{
	int direction;
	u32 x1_tmp, x2_tmp, y1_tmp, y2_tmp;

	direction = 0x0004;

	if ((x1 < x2) && (y1 == y2)) {
		direction |= 0x0200;
		x1_tmp = x1 + w - 1;
		x2_tmp = x2 + w - 1;
	} else {
		x1_tmp = x1;
		x2_tmp = x2;
	}

	if (y1 < y2) {
		direction |= 0x0100;
		y1_tmp = y1 + h - 1;
		y2_tmp = y2 + h - 1;
	} else {
		y1_tmp = y1;
		y2_tmp = y2;
	}

	writemmr(par, 0x2128, direction);
	t_outb(par, ROP_S, 0x2127);
	writemmr(par, 0x213C, masked_point(y1_tmp, x1_tmp));
	writemmr(par, 0x2138, masked_point(y2_tmp, x2_tmp));
	writemmr(par, 0x2140, masked_point(h, w));
	t_outb(par, 0x01, 0x2124);
}

/*
 * Image specific acceleration functions
 */
static void image_init_accel(struct tridentfb_par *par, int pitch, int bpp)
{
	int tmp = 0;
	switch (bpp) {
	case 8:
		tmp = 0;
		break;
	case 15:
		tmp = 5;
		break;
	case 16:
		tmp = 1;
		break;
	case 24:
	case 32:
		tmp = 2;
		break;
	}
	writemmr(par, 0x2120, 0xF0000000);
	writemmr(par, 0x2120, 0x40000000 | tmp);
	writemmr(par, 0x2120, 0x80000000);
	writemmr(par, 0x2144, 0x00000000);
	writemmr(par, 0x2148, 0x00000000);
	writemmr(par, 0x2150, 0x00000000);
	writemmr(par, 0x2154, 0x00000000);
	writemmr(par, 0x2120, 0x60000000 | (pitch << 16) | pitch);
	writemmr(par, 0x216C, 0x00000000);
	writemmr(par, 0x2170, 0x00000000);
	writemmr(par, 0x217C, 0x00000000);
	writemmr(par, 0x2120, 0x10000000);
	writemmr(par, 0x2130, (2047 << 16) | 2047);
}

static void image_wait_engine(struct tridentfb_par *par)
{
	while (readmmr(par, 0x2164) & 0xF0000000) ;
}

static void image_fill_rect(struct tridentfb_par *par,
			    u32 x, u32 y, u32 w, u32 h, u32 c, u32 rop)
{
	writemmr(par, 0x2120, 0x80000000);
	writemmr(par, 0x2120, 0x90000000 | ROP_S);

	writemmr(par, 0x2144, c);

	writemmr(par, DR1, point(x, y));
	writemmr(par, DR2, point(x + w - 1, y + h - 1));

	writemmr(par, 0x2124, 0x80000000 | 3 << 22 | 1 << 10 | 1 << 9);
}

static void image_copy_rect(struct tridentfb_par *par,
			    u32 x1, u32 y1, u32 x2, u32 y2, u32 w, u32 h)
{
	u32 s1, s2, d1, d2;
	int direction = 2;
	s1 = point(x1, y1);
	s2 = point(x1 + w - 1, y1 + h - 1);
	d1 = point(x2, y2);
	d2 = point(x2 + w - 1, y2 + h - 1);

	if ((y1 > y2) || ((y1 == y2) && (x1 > x2)))
		direction = 0;

	writemmr(par, 0x2120, 0x80000000);
	writemmr(par, 0x2120, 0x90000000 | ROP_S);

	writemmr(par, SR1, direction ? s2 : s1);
	writemmr(par, SR2, direction ? s1 : s2);
	writemmr(par, DR1, direction ? d2 : d1);
	writemmr(par, DR2, direction ? d1 : d2);
	writemmr(par, 0x2124,
		 0x80000000 | 1 << 22 | 1 << 10 | 1 << 7 | direction);
}

/*
 * Accel functions called by the upper layers
 */
#ifdef CONFIG_FB_TRIDENT_ACCEL
static void tridentfb_fillrect(struct fb_info *info,
			       const struct fb_fillrect *fr)
{
	struct tridentfb_par *par = info->par;
	int bpp = info->var.bits_per_pixel;
	int col = 0;

	switch (bpp) {
	default:
	case 8:
		col |= fr->color;
		col |= col << 8;
		col |= col << 16;
		break;
	case 16:
		col = ((u32 *)(info->pseudo_palette))[fr->color];
		break;
	case 32:
		col = ((u32 *)(info->pseudo_palette))[fr->color];
		break;
	}

	par->fill_rect(par, fr->dx, fr->dy, fr->width,
		       fr->height, col, fr->rop);
	par->wait_engine(par);
}
static void tridentfb_copyarea(struct fb_info *info,
			       const struct fb_copyarea *ca)
{
	struct tridentfb_par *par = info->par;

	par->copy_rect(par, ca->sx, ca->sy, ca->dx, ca->dy,
		       ca->width, ca->height);
	par->wait_engine(par);
}
#else /* !CONFIG_FB_TRIDENT_ACCEL */
#define tridentfb_fillrect cfb_fillrect
#define tridentfb_copyarea cfb_copyarea
#endif /* CONFIG_FB_TRIDENT_ACCEL */


/*
 * Hardware access functions
 */

static inline unsigned char read3X4(struct tridentfb_par *par, int reg)
{
	return vga_mm_rcrt(par->io_virt, reg);
}

static inline void write3X4(struct tridentfb_par *par, int reg,
			    unsigned char val)
{
	vga_mm_wcrt(par->io_virt, reg, val);
}

static inline unsigned char read3CE(struct tridentfb_par *par,
				    unsigned char reg)
{
	return vga_mm_rgfx(par->io_virt, reg);
}

static inline void writeAttr(struct tridentfb_par *par, int reg,
			     unsigned char val)
{
	fb_readb(par->io_virt + VGA_IS1_RC);	/* flip-flop to index */
	vga_mm_wattr(par->io_virt, reg, val);
}

static inline void write3CE(struct tridentfb_par *par, int reg,
			    unsigned char val)
{
	vga_mm_wgfx(par->io_virt, reg, val);
}

static void enable_mmio(void)
{
	/* Goto New Mode */
	vga_io_rseq(0x0B);

	/* Unprotect registers */
	vga_io_wseq(NewMode1, 0x80);

	/* Enable MMIO */
	outb(PCIReg, 0x3D4);
	outb(inb(0x3D5) | 0x01, 0x3D5);
}

static void disable_mmio(struct tridentfb_par *par)
{
	/* Goto New Mode */
	vga_mm_rseq(par->io_virt, 0x0B);

	/* Unprotect registers */
	vga_mm_wseq(par->io_virt, NewMode1, 0x80);

	/* Disable MMIO */
	t_outb(par, PCIReg, 0x3D4);
	t_outb(par, t_inb(par, 0x3D5) & ~0x01, 0x3D5);
}

static void crtc_unlock(struct tridentfb_par *par)
{
	write3X4(par, VGA_CRTC_V_SYNC_END,
		 read3X4(par, VGA_CRTC_V_SYNC_END) & 0x7F);
}

/*  Return flat panel's maximum x resolution */
static int __devinit get_nativex(struct tridentfb_par *par)
{
	int x, y, tmp;

	if (nativex)
		return nativex;

	tmp = (read3CE(par, VertStretch) >> 4) & 3;

	switch (tmp) {
	case 0:
		x = 1280; y = 1024;
		break;
	case 2:
		x = 1024; y = 768;
		break;
	case 3:
		x = 800; y = 600;
		break;
	case 4:
		x = 1400; y = 1050;
		break;
	case 1:
	default:
		x = 640;  y = 480;
		break;
	}

	output("%dx%d flat panel found\n", x, y);
	return x;
}

/* Set pitch */
static void set_lwidth(struct tridentfb_par *par, int width)
{
	write3X4(par, VGA_CRTC_OFFSET, width & 0xFF);
	write3X4(par, AddColReg,
		 (read3X4(par, AddColReg) & 0xCF) | ((width & 0x300) >> 4));
}

/* For resolutions smaller than FP resolution stretch */
static void screen_stretch(struct tridentfb_par *par)
{
	if (par->chip_id != CYBERBLADEXPAi1)
		write3CE(par, BiosReg, 0);
	else
		write3CE(par, BiosReg, 8);
	write3CE(par, VertStretch, (read3CE(par, VertStretch) & 0x7C) | 1);
	write3CE(par, HorStretch, (read3CE(par, HorStretch) & 0x7C) | 1);
}

/* For resolutions smaller than FP resolution center */
static void screen_center(struct tridentfb_par *par)
{
	write3CE(par, VertStretch, (read3CE(par, VertStretch) & 0x7C) | 0x80);
	write3CE(par, HorStretch, (read3CE(par, HorStretch) & 0x7C) | 0x80);
}

/* Address of first shown pixel in display memory */
static void set_screen_start(struct tridentfb_par *par, int base)
{
	u8 tmp;
	write3X4(par, VGA_CRTC_START_LO, base & 0xFF);
	write3X4(par, VGA_CRTC_START_HI, (base & 0xFF00) >> 8);
	tmp = read3X4(par, CRTCModuleTest) & 0xDF;
	write3X4(par, CRTCModuleTest, tmp | ((base & 0x10000) >> 11));
	tmp = read3X4(par, CRTHiOrd) & 0xF8;
	write3X4(par, CRTHiOrd, tmp | ((base & 0xE0000) >> 17));
}

/* Set dotclock frequency */
static void set_vclk(struct tridentfb_par *par, unsigned long freq)
{
	int m, n, k;
	unsigned long fi, d, di;
	unsigned char best_m = 0, best_n = 0, best_k = 0;
	unsigned char hi, lo;

	d = 20000;
	for (k = 1; k >= 0; k--)
		for (m = 0; m < 32; m++)
			for (n = 0; n < 122; n++) {
				fi = ((14318l * (n + 8)) / (m + 2)) >> k;
				if ((di = abs(fi - freq)) < d) {
					d = di;
					best_n = n;
					best_m = m;
					best_k = k;
				}
				if (fi > freq)
					break;
			}

	if (is_oldclock(par->chip_id)) {
		lo = best_n | (best_m << 7);
		hi = (best_m >> 1) | (best_k << 4);
	} else {
		lo = best_n;
		hi = best_m | (best_k << 6);
	}

	if (is3Dchip(par->chip_id)) {
		vga_mm_wseq(par->io_virt, ClockHigh, hi);
		vga_mm_wseq(par->io_virt, ClockLow, lo);
	} else {
		t_outb(par, lo, 0x43C8);
		t_outb(par, hi, 0x43C9);
	}
	debug("VCLK = %X %X\n", hi, lo);
}

/* Set number of lines for flat panels*/
static void set_number_of_lines(struct tridentfb_par *par, int lines)
{
	int tmp = read3CE(par, CyberEnhance) & 0x8F;
	if (lines > 1024)
		tmp |= 0x50;
	else if (lines > 768)
		tmp |= 0x30;
	else if (lines > 600)
		tmp |= 0x20;
	else if (lines > 480)
		tmp |= 0x10;
	write3CE(par, CyberEnhance, tmp);
}

/*
 * If we see that FP is active we assume we have one.
 * Otherwise we have a CRT display. User can override.
 */
static int __devinit is_flatpanel(struct tridentfb_par *par)
{
	if (fp)
		return 1;
	if (crt || !iscyber(par->chip_id))
		return 0;
	return (read3CE(par, FPConfig) & 0x10) ? 1 : 0;
}

/* Try detecting the video memory size */
static unsigned int __devinit get_memsize(struct tridentfb_par *par)
{
	unsigned char tmp, tmp2;
	unsigned int k;

	/* If memory size provided by user */
	if (memsize)
		k = memsize * Kb;
	else
		switch (par->chip_id) {
		case CYBER9525DVD:
			k = 2560 * Kb;
			break;
		default:
			tmp = read3X4(par, SPR) & 0x0F;
			switch (tmp) {

			case 0x01:
				k = 512 * Kb;
				break;
			case 0x02:
				k = 6 * Mb;	/* XP */
				break;
			case 0x03:
				k = 1 * Mb;
				break;
			case 0x04:
				k = 8 * Mb;
				break;
			case 0x06:
				k = 10 * Mb;	/* XP */
				break;
			case 0x07:
				k = 2 * Mb;
				break;
			case 0x08:
				k = 12 * Mb;	/* XP */
				break;
			case 0x0A:
				k = 14 * Mb;	/* XP */
				break;
			case 0x0C:
				k = 16 * Mb;	/* XP */
				break;
			case 0x0E:		/* XP */

				tmp2 = vga_mm_rseq(par->io_virt, 0xC1);
				switch (tmp2) {
				case 0x00:
					k = 20 * Mb;
					break;
				case 0x01:
					k = 24 * Mb;
					break;
				case 0x10:
					k = 28 * Mb;
					break;
				case 0x11:
					k = 32 * Mb;
					break;
				default:
					k = 1 * Mb;
					break;
				}
				break;

			case 0x0F:
				k = 4 * Mb;
				break;
			default:
				k = 1 * Mb;
				break;
			}
		}

	k -= memdiff * Kb;
	output("framebuffer size = %d Kb\n", k / Kb);
	return k;
}

/* See if we can handle the video mode described in var */
static int tridentfb_check_var(struct fb_var_screeninfo *var,
			       struct fb_info *info)
{
	struct tridentfb_par *par = info->par;
	int bpp = var->bits_per_pixel;
	debug("enter\n");

	/* check color depth */
	if (bpp == 24)
		bpp = var->bits_per_pixel = 32;
	/* check whether resolution fits on panel and in memory */
	if (par->flatpanel && nativex && var->xres > nativex)
		return -EINVAL;
	if (var->xres * var->yres_virtual * bpp / 8 > info->fix.smem_len)
		return -EINVAL;

	switch (bpp) {
	case 8:
		var->red.offset = 0;
		var->green.offset = 0;
		var->blue.offset = 0;
		var->red.length = 6;
		var->green.length = 6;
		var->blue.length = 6;
		break;
	case 16:
		var->red.offset = 11;
		var->green.offset = 5;
		var->blue.offset = 0;
		var->red.length = 5;
		var->green.length = 6;
		var->blue.length = 5;
		break;
	case 32:
		var->red.offset = 16;
		var->green.offset = 8;
		var->blue.offset = 0;
		var->red.length = 8;
		var->green.length = 8;
		var->blue.length = 8;
		break;
	default:
		return -EINVAL;
	}
	debug("exit\n");

	return 0;

}

/* Pan the display */
static int tridentfb_pan_display(struct fb_var_screeninfo *var,
				 struct fb_info *info)
{
	struct tridentfb_par *par = info->par;
	unsigned int offset;

	debug("enter\n");
	offset = (var->xoffset + (var->yoffset * var->xres))
		* var->bits_per_pixel / 32;
	info->var.xoffset = var->xoffset;
	info->var.yoffset = var->yoffset;
	set_screen_start(par, offset);
	debug("exit\n");
	return 0;
}

static void shadowmode_on(struct tridentfb_par *par)
{
	write3CE(par, CyberControl, read3CE(par, CyberControl) | 0x81);
}

static void shadowmode_off(struct tridentfb_par *par)
{
	write3CE(par, CyberControl, read3CE(par, CyberControl) & 0x7E);
}

/* Set the hardware to the requested video mode */
static int tridentfb_set_par(struct fb_info *info)
{
	struct tridentfb_par *par = (struct tridentfb_par *)(info->par);
	u32 htotal, hdispend, hsyncstart, hsyncend, hblankstart, hblankend;
	u32 vtotal, vdispend, vsyncstart, vsyncend, vblankstart, vblankend;
	struct fb_var_screeninfo *var = &info->var;
	int bpp = var->bits_per_pixel;
	unsigned char tmp;
	unsigned long vclk;

	debug("enter\n");
	hdispend = var->xres / 8 - 1;
	hsyncstart = (var->xres + var->right_margin) / 8 - 1;
	hsyncend = (var->xres + var->right_margin + var->hsync_len) / 8 - 1;
	htotal = (var->xres + var->left_margin + var->right_margin +
		  var->hsync_len) / 8 - 5;
	hblankstart = hdispend + 2;
	hblankend = htotal + 3;

	vdispend = var->yres - 1;
	vsyncstart = var->yres + var->lower_margin;
	vsyncend = vsyncstart + var->vsync_len;
	vtotal = var->upper_margin + vsyncend - 2;
	vblankstart = vdispend + 2;
	vblankend = vtotal;

	crtc_unlock(par);
	write3CE(par, CyberControl, 8);

	if (par->flatpanel && var->xres < nativex) {
		/*
		 * on flat panels with native size larger
		 * than requested resolution decide whether
		 * we stretch or center
		 */
		t_outb(par, 0xEB, VGA_MIS_W);

		shadowmode_on(par);

		if (center)
			screen_center(par);
		else if (stretch)
			screen_stretch(par);

	} else {
		t_outb(par, 0x2B, VGA_MIS_W);
		write3CE(par, CyberControl, 8);
	}

	/* vertical timing values */
	write3X4(par, VGA_CRTC_V_TOTAL, vtotal & 0xFF);
	write3X4(par, VGA_CRTC_V_DISP_END, vdispend & 0xFF);
	write3X4(par, VGA_CRTC_V_SYNC_START, vsyncstart & 0xFF);
	write3X4(par, VGA_CRTC_V_SYNC_END, (vsyncend & 0x0F));
	write3X4(par, VGA_CRTC_V_BLANK_START, vblankstart & 0xFF);
	write3X4(par, VGA_CRTC_V_BLANK_END, vblankend & 0xFF);

	/* horizontal timing values */
	write3X4(par, VGA_CRTC_H_TOTAL, htotal & 0xFF);
	write3X4(par, VGA_CRTC_H_DISP, hdispend & 0xFF);
	write3X4(par, VGA_CRTC_H_SYNC_START, hsyncstart & 0xFF);
	write3X4(par, VGA_CRTC_H_SYNC_END,
		 (hsyncend & 0x1F) | ((hblankend & 0x20) << 2));
	write3X4(par, VGA_CRTC_H_BLANK_START, hblankstart & 0xFF);
	write3X4(par, VGA_CRTC_H_BLANK_END, hblankend & 0x1F);

	/* higher bits of vertical timing values */
	tmp = 0x10;
	if (vtotal & 0x100) tmp |= 0x01;
	if (vdispend & 0x100) tmp |= 0x02;
	if (vsyncstart & 0x100) tmp |= 0x04;
	if (vblankstart & 0x100) tmp |= 0x08;

	if (vtotal & 0x200) tmp |= 0x20;
	if (vdispend & 0x200) tmp |= 0x40;
	if (vsyncstart & 0x200) tmp |= 0x80;
	write3X4(par, VGA_CRTC_OVERFLOW, tmp);

	tmp = read3X4(par, CRTHiOrd) & 0x07;
	tmp |= 0x08;	/* line compare bit 10 */
	if (vtotal & 0x400) tmp |= 0x80;
	if (vblankstart & 0x400) tmp |= 0x40;
	if (vsyncstart & 0x400) tmp |= 0x20;
	if (vdispend & 0x400) tmp |= 0x10;
	write3X4(par, CRTHiOrd, tmp);

	tmp = (htotal >> 8) & 0x01;
	tmp |= (hdispend >> 7) & 0x02;
	tmp |= (hsyncstart >> 5) & 0x08;
	tmp |= (hblankstart >> 4) & 0x10;
	write3X4(par, HorizOverflow, tmp);

	tmp = 0x40;
	if (vblankstart & 0x200) tmp |= 0x20;
//FIXME	if (info->var.vmode & FB_VMODE_DOUBLE) tmp |= 0x80;  /* double scan for 200 line modes */
	write3X4(par, VGA_CRTC_MAX_SCAN, tmp);

	write3X4(par, VGA_CRTC_LINE_COMPARE, 0xFF);
	write3X4(par, VGA_CRTC_PRESET_ROW, 0);
	write3X4(par, VGA_CRTC_MODE, 0xC3);

	write3X4(par, LinearAddReg, 0x20);	/* enable linear addressing */

	tmp = (info->var.vmode & FB_VMODE_INTERLACED) ? 0x84 : 0x80;
	/* enable access extended memory */
	write3X4(par, CRTCModuleTest, tmp);

	/* enable GE for text acceleration */
	write3X4(par, GraphEngReg, 0x80);

#ifdef CONFIG_FB_TRIDENT_ACCEL
	par->init_accel(par, info->var.xres, bpp);
#endif

	switch (bpp) {
	case 8:
		tmp = 0x00;
		break;
	case 16:
		tmp = 0x05;
		break;
	case 24:
		tmp = 0x29;
		break;
	case 32:
		tmp = 0x09;
		break;
	}

	write3X4(par, PixelBusReg, tmp);

	tmp = 0x10;
	if (iscyber(par->chip_id))
		tmp |= 0x20;
	write3X4(par, DRAMControl, tmp);	/* both IO, linear enable */

	write3X4(par, InterfaceSel, read3X4(par, InterfaceSel) | 0x40);
	write3X4(par, Performance, 0x92);
	/* MMIO & PCI read and write burst enable */
	write3X4(par, PCIReg, 0x07);

	/* convert from picoseconds to kHz */
	vclk = PICOS2KHZ(info->var.pixclock);
	if (bpp == 32)
		vclk *= 2;
	set_vclk(par, vclk);

	vga_mm_wseq(par->io_virt, 0, 3);
	vga_mm_wseq(par->io_virt, 1, 1); /* set char clock 8 dots wide */
	/* enable 4 maps because needed in chain4 mode */
	vga_mm_wseq(par->io_virt, 2, 0x0F);
	vga_mm_wseq(par->io_virt, 3, 0);
	vga_mm_wseq(par->io_virt, 4, 0x0E); /* memory mode enable bitmaps ?? */

	/* divide clock by 2 if 32bpp chain4 mode display and CPU path */
	write3CE(par, MiscExtFunc, (bpp == 32) ? 0x1A : 0x12);
	write3CE(par, 0x5, 0x40);	/* no CGA compat, allow 256 col */
	write3CE(par, 0x6, 0x05);	/* graphics mode */
	write3CE(par, 0x7, 0x0F);	/* planes? */

	if (par->chip_id == CYBERBLADEXPAi1) {
		/* This fixes snow-effect in 32 bpp */
		write3X4(par, VGA_CRTC_H_SYNC_START, 0x84);
	}

	/* graphics mode and support 256 color modes */
	writeAttr(par, 0x10, 0x41);
	writeAttr(par, 0x12, 0x0F);	/* planes */
	writeAttr(par, 0x13, 0);	/* horizontal pel panning */

	/* colors */
	for (tmp = 0; tmp < 0x10; tmp++)
		writeAttr(par, tmp, tmp);
	fb_readb(par->io_virt + VGA_IS1_RC);	/* flip-flop to index */
	t_outb(par, 0x20, VGA_ATT_W);		/* enable attr */

	switch (bpp) {
	case 8:
		tmp = 0;
		break;
	case 15:
		tmp = 0x10;
		break;
	case 16:
		tmp = 0x30;
		break;
	case 24:
	case 32:
		tmp = 0xD0;
		break;
	}

	t_inb(par, VGA_PEL_IW);
	t_inb(par, VGA_PEL_MSK);
	t_inb(par, VGA_PEL_MSK);
	t_inb(par, VGA_PEL_MSK);
	t_inb(par, VGA_PEL_MSK);
	t_outb(par, tmp, VGA_PEL_MSK);
	t_inb(par, VGA_PEL_IW);

	if (par->flatpanel)
		set_number_of_lines(par, info->var.yres);
	set_lwidth(par, info->var.xres * bpp / (4 * 16));
	info->fix.visual = (bpp == 8) ? FB_VISUAL_PSEUDOCOLOR : FB_VISUAL_TRUECOLOR;
	info->fix.line_length = info->var.xres * (bpp >> 3);
	info->cmap.len = (bpp == 8) ? 256 : 16;
	debug("exit\n");
	return 0;
}

/* Set one color register */
static int tridentfb_setcolreg(unsigned regno, unsigned red, unsigned green,
			       unsigned blue, unsigned transp,
			       struct fb_info *info)
{
	int bpp = info->var.bits_per_pixel;
	struct tridentfb_par *par = info->par;

	if (regno >= info->cmap.len)
		return 1;

	if (bpp == 8) {
		t_outb(par, 0xFF, VGA_PEL_MSK);
		t_outb(par, regno, VGA_PEL_IW);

		t_outb(par, red >> 10, VGA_PEL_D);
		t_outb(par, green >> 10, VGA_PEL_D);
		t_outb(par, blue >> 10, VGA_PEL_D);

	} else if (regno < 16) {
		if (bpp == 16) {	/* RGB 565 */
			u32 col;

			col = (red & 0xF800) | ((green & 0xFC00) >> 5) |
				((blue & 0xF800) >> 11);
			col |= col << 16;
			((u32 *)(info->pseudo_palette))[regno] = col;
		} else if (bpp == 32)		/* ARGB 8888 */
			((u32*)info->pseudo_palette)[regno] =
				((transp & 0xFF00) << 16)	|
				((red & 0xFF00) << 8)		|
				((green & 0xFF00))		|
				((blue & 0xFF00) >> 8);
	}

/* 	debug("exit\n"); */
	return 0;
}

/* Try blanking the screen.For flat panels it does nothing */
static int tridentfb_blank(int blank_mode, struct fb_info *info)
{
	unsigned char PMCont, DPMSCont;
	struct tridentfb_par *par = info->par;

	debug("enter\n");
	if (par->flatpanel)
		return 0;
	t_outb(par, 0x04, 0x83C8); /* Read DPMS Control */
	PMCont = t_inb(par, 0x83C6) & 0xFC;
	DPMSCont = read3CE(par, PowerStatus) & 0xFC;
	switch (blank_mode) {
	case FB_BLANK_UNBLANK:
		/* Screen: On, HSync: On, VSync: On */
	case FB_BLANK_NORMAL:
		/* Screen: Off, HSync: On, VSync: On */
		PMCont |= 0x03;
		DPMSCont |= 0x00;
		break;
	case FB_BLANK_HSYNC_SUSPEND:
		/* Screen: Off, HSync: Off, VSync: On */
		PMCont |= 0x02;
		DPMSCont |= 0x01;
		break;
	case FB_BLANK_VSYNC_SUSPEND:
		/* Screen: Off, HSync: On, VSync: Off */
		PMCont |= 0x02;
		DPMSCont |= 0x02;
		break;
	case FB_BLANK_POWERDOWN:
		/* Screen: Off, HSync: Off, VSync: Off */
		PMCont |= 0x00;
		DPMSCont |= 0x03;
		break;
	}

	write3CE(par, PowerStatus, DPMSCont);
	t_outb(par, 4, 0x83C8);
	t_outb(par, PMCont, 0x83C6);

	debug("exit\n");

	/* let fbcon do a softblank for us */
	return (blank_mode == FB_BLANK_NORMAL) ? 1 : 0;
}

static struct fb_ops tridentfb_ops = {
	.owner = THIS_MODULE,
	.fb_setcolreg = tridentfb_setcolreg,
	.fb_pan_display = tridentfb_pan_display,
	.fb_blank = tridentfb_blank,
	.fb_check_var = tridentfb_check_var,
	.fb_set_par = tridentfb_set_par,
	.fb_fillrect = tridentfb_fillrect,
	.fb_copyarea = tridentfb_copyarea,
	.fb_imageblit = cfb_imageblit,
};

static int __devinit trident_pci_probe(struct pci_dev *dev,
				       const struct pci_device_id *id)
{
	int err;
	unsigned char revision;
	struct fb_info *info;
	struct tridentfb_par *default_par;
	int defaultaccel;
	int chip3D;
	int chip_id;

	err = pci_enable_device(dev);
	if (err)
		return err;

	info = framebuffer_alloc(sizeof(struct tridentfb_par), &dev->dev);
	if (!info)
		return -ENOMEM;
	default_par = info->par;

	chip_id = id->device;

	if (chip_id == CYBERBLADEi1)
		output("*** Please do use cyblafb, Cyberblade/i1 support "
		       "will soon be removed from tridentfb!\n");


	/* If PCI id is 0x9660 then further detect chip type */

	if (chip_id == TGUI9660) {
		revision = vga_io_rseq(RevisionID);

		switch (revision) {
		case 0x22:
		case 0x23:
			chip_id = CYBER9397;
			break;
		case 0x2A:
			chip_id = CYBER9397DVD;
			break;
		case 0x30:
		case 0x33:
		case 0x34:
		case 0x35:
		case 0x38:
		case 0x3A:
		case 0xB3:
			chip_id = CYBER9385;
			break;
		case 0x40 ... 0x43:
			chip_id = CYBER9382;
			break;
		case 0x4A:
			chip_id = CYBER9388;
			break;
		default:
			break;
		}
	}

	chip3D = is3Dchip(chip_id);

	if (is_xp(chip_id)) {
		default_par->init_accel = xp_init_accel;
		default_par->wait_engine = xp_wait_engine;
		default_par->fill_rect = xp_fill_rect;
		default_par->copy_rect = xp_copy_rect;
	} else if (is_blade(chip_id)) {
		default_par->init_accel = blade_init_accel;
		default_par->wait_engine = blade_wait_engine;
		default_par->fill_rect = blade_fill_rect;
		default_par->copy_rect = blade_copy_rect;
	} else {
		default_par->init_accel = image_init_accel;
		default_par->wait_engine = image_wait_engine;
		default_par->fill_rect = image_fill_rect;
		default_par->copy_rect = image_copy_rect;
	}

	default_par->chip_id = chip_id;

	/* acceleration is on by default for 3D chips */
	defaultaccel = chip3D && !noaccel;

	/* setup MMIO region */
	tridentfb_fix.mmio_start = pci_resource_start(dev, 1);
	tridentfb_fix.mmio_len = chip3D ? 0x20000 : 0x10000;

	if (!request_mem_region(tridentfb_fix.mmio_start, tridentfb_fix.mmio_len, "tridentfb")) {
		debug("request_region failed!\n");
		framebuffer_release(info);
		return -1;
	}

	default_par->io_virt = ioremap_nocache(tridentfb_fix.mmio_start,
					       tridentfb_fix.mmio_len);

	if (!default_par->io_virt) {
		debug("ioremap failed\n");
		err = -1;
		goto out_unmap1;
	}

	/* setup framebuffer memory */
	tridentfb_fix.smem_start = pci_resource_start(dev, 0);
	tridentfb_fix.smem_len = get_memsize(default_par);

	if (!request_mem_region(tridentfb_fix.smem_start, tridentfb_fix.smem_len, "tridentfb")) {
		debug("request_mem_region failed!\n");
		disable_mmio(info->par);
		err = -1;
		goto out_unmap1;
	}

	enable_mmio();

	info->screen_base = ioremap_nocache(tridentfb_fix.smem_start,
					    tridentfb_fix.smem_len);

	if (!info->screen_base) {
		debug("ioremap failed\n");
		err = -1;
		goto out_unmap2;
	}

	output("%s board found\n", pci_name(dev));
	default_par->flatpanel = is_flatpanel(default_par);

	if (default_par->flatpanel)
		nativex = get_nativex(default_par);

	info->fix = tridentfb_fix;
	info->fbops = &tridentfb_ops;


	info->flags = FBINFO_DEFAULT | FBINFO_HWACCEL_YPAN;
#ifdef CONFIG_FB_TRIDENT_ACCEL
	info->flags |= FBINFO_HWACCEL_COPYAREA | FBINFO_HWACCEL_FILLRECT;
#endif
	if (!fb_find_mode(&info->var, info,
			  mode_option, NULL, 0, NULL, bpp)) {
		err = -EINVAL;
		goto out_unmap2;
	}
	err = fb_alloc_cmap(&info->cmap, 256, 0);
	if (err < 0)
		goto out_unmap2;

	if (defaultaccel && default_par->init_accel)
		info->var.accel_flags |= FB_ACCELF_TEXT;
	else
		info->var.accel_flags &= ~FB_ACCELF_TEXT;
	info->var.activate |= FB_ACTIVATE_NOW;
	info->device = &dev->dev;
	if (register_framebuffer(info) < 0) {
		printk(KERN_ERR "tridentfb: could not register Trident framebuffer\n");
		fb_dealloc_cmap(&info->cmap);
		err = -EINVAL;
		goto out_unmap2;
	}
	output("fb%d: %s frame buffer device %dx%d-%dbpp\n",
	   info->node, info->fix.id, info->var.xres,
	   info->var.yres, info->var.bits_per_pixel);

	pci_set_drvdata(dev, info);
	return 0;

out_unmap2:
	if (info->screen_base)
		iounmap(info->screen_base);
	release_mem_region(tridentfb_fix.smem_start, tridentfb_fix.smem_len);
	disable_mmio(info->par);
out_unmap1:
	if (default_par->io_virt)
		iounmap(default_par->io_virt);
	release_mem_region(tridentfb_fix.mmio_start, tridentfb_fix.mmio_len);
	framebuffer_release(info);
	return err;
}

static void __devexit trident_pci_remove(struct pci_dev *dev)
{
	struct fb_info *info = pci_get_drvdata(dev);
	struct tridentfb_par *par = info->par;

	unregister_framebuffer(info);
	iounmap(par->io_virt);
	iounmap(info->screen_base);
	release_mem_region(tridentfb_fix.smem_start, tridentfb_fix.smem_len);
	release_mem_region(tridentfb_fix.mmio_start, tridentfb_fix.mmio_len);
	pci_set_drvdata(dev, NULL);
	framebuffer_release(info);
}

/* List of boards that we are trying to support */
static struct pci_device_id trident_devices[] = {
	{PCI_VENDOR_ID_TRIDENT,	BLADE3D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEi7, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEi7D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEi1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEi1D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEAi1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEAi1D, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEE4, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	TGUI9660, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	IMAGE975, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	IMAGE985, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9320, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9388, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9520, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9525DVD, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9397, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBER9397DVD, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEXPAi1, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEXPm8, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{PCI_VENDOR_ID_TRIDENT,	CYBERBLADEXPm16, PCI_ANY_ID, PCI_ANY_ID, 0, 0, 0},
	{0,}
};

MODULE_DEVICE_TABLE(pci, trident_devices);

static struct pci_driver tridentfb_pci_driver = {
	.name = "tridentfb",
	.id_table = trident_devices,
	.probe = trident_pci_probe,
	.remove = __devexit_p(trident_pci_remove)
};

/*
 * Parse user specified options (`video=trident:')
 * example:
 *	video=trident:800x600,bpp=16,noaccel
 */
#ifndef MODULE
static int __init tridentfb_setup(char *options)
{
	char *opt;
	if (!options || !*options)
		return 0;
	while ((opt = strsep(&options, ",")) != NULL) {
		if (!*opt)
			continue;
		if (!strncmp(opt, "noaccel", 7))
			noaccel = 1;
		else if (!strncmp(opt, "fp", 2))
			fp = 1;
		else if (!strncmp(opt, "crt", 3))
			fp = 0;
		else if (!strncmp(opt, "bpp=", 4))
			bpp = simple_strtoul(opt + 4, NULL, 0);
		else if (!strncmp(opt, "center", 6))
			center = 1;
		else if (!strncmp(opt, "stretch", 7))
			stretch = 1;
		else if (!strncmp(opt, "memsize=", 8))
			memsize = simple_strtoul(opt + 8, NULL, 0);
		else if (!strncmp(opt, "memdiff=", 8))
			memdiff = simple_strtoul(opt + 8, NULL, 0);
		else if (!strncmp(opt, "nativex=", 8))
			nativex = simple_strtoul(opt + 8, NULL, 0);
		else
			mode_option = opt;
	}
	return 0;
}
#endif

static int __init tridentfb_init(void)
{
#ifndef MODULE
	char *option = NULL;

	if (fb_get_options("tridentfb", &option))
		return -ENODEV;
	tridentfb_setup(option);
#endif
	output("Trident framebuffer %s initializing\n", VERSION);
	return pci_register_driver(&tridentfb_pci_driver);
}

static void __exit tridentfb_exit(void)
{
	pci_unregister_driver(&tridentfb_pci_driver);
}

module_init(tridentfb_init);
module_exit(tridentfb_exit);

MODULE_AUTHOR("Jani Monoses <jani@iv.ro>");
MODULE_DESCRIPTION("Framebuffer driver for Trident cards");
MODULE_LICENSE("GPL");

