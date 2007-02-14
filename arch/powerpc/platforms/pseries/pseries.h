/*
 * Copyright 2006 IBM Corporation.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version
 * 2 of the License, or (at your option) any later version.
 */

#ifndef _PSERIES_PSERIES_H
#define _PSERIES_PSERIES_H

extern void __init fw_feature_init(void);

struct pt_regs;

extern int pSeries_system_reset_exception(struct pt_regs *regs);
extern int pSeries_machine_check_exception(struct pt_regs *regs);

#ifdef CONFIG_SMP
extern void smp_init_pseries_mpic(void);
extern void smp_init_pseries_xics(void);
#else
static inline smp_init_pseries_mpic(void) { };
static inline smp_init_pseries_xics(void) { };
#endif

#endif /* _PSERIES_PSERIES_H */
