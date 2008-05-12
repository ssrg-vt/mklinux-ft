#ifndef _ASM_X8664_IOMMU_H
#define _ASM_X8664_IOMMU_H 1

extern void pci_iommu_shutdown(void);
extern void no_iommu_init(void);
extern int force_iommu, no_iommu;
extern int iommu_detected;
extern int agp_amd64_init(void);
#ifdef CONFIG_GART_IOMMU
extern void gart_iommu_init(void);
extern void gart_iommu_shutdown(void);
extern void __init gart_parse_options(char *);
extern void early_gart_iommu_check(void);
extern void gart_iommu_hole_init(void);
extern int fallback_aper_order;
extern int fallback_aper_force;
extern int gart_iommu_aperture;
extern int gart_iommu_aperture_allowed;
extern int gart_iommu_aperture_disabled;
extern int fix_aperture;
#else
#define gart_iommu_aperture 0
#define gart_iommu_aperture_allowed 0

static inline void early_gart_iommu_check(void)
{
}

static inline void gart_iommu_shutdown(void)
{
}

#endif

/* PTE bits. */
#define GPTE_VALID	1
#define GPTE_COHERENT	2

/* Aperture control register bits. */
#define GARTEN		(1<<0)
#define DISGARTCPU	(1<<4)
#define DISGARTIO	(1<<5)

/* GART cache control register bits. */
#define INVGART		(1<<0)
#define GARTPTEERR	(1<<1)

/* K8 On-cpu GART registers */
#define AMD64_GARTAPERTURECTL	0x90
#define AMD64_GARTAPERTUREBASE	0x94
#define AMD64_GARTTABLEBASE	0x98
#define AMD64_GARTCACHECTL	0x9c
#define AMD64_GARTEN		(1<<0)

static inline void enable_gart_translation(struct pci_dev *dev, u64 addr)
{
	u32 tmp, ctl;

        /* address of the mappings table */
        addr >>= 12;
        tmp = (u32) addr<<4;
        tmp &= ~0xf;
        pci_write_config_dword(dev, AMD64_GARTTABLEBASE, tmp);

        /* Enable GART translation for this hammer. */
        pci_read_config_dword(dev, AMD64_GARTAPERTURECTL, &ctl);
        ctl |= GARTEN;
        ctl &= ~(DISGARTCPU | DISGARTIO);
        pci_write_config_dword(dev, AMD64_GARTAPERTURECTL, ctl);
}

#endif
