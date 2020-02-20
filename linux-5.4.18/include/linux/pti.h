// SPDX-License-Identifier: GPL-2.0
#ifndef _INCLUDE_PTI_H  /* PTI: CONFIG_PAGE_TABLE_ISOLATION. Remove the kernel mapping in user mode. For x64 */
#define _INCLUDE_PTI_H

#ifdef CONFIG_PAGE_TABLE_ISOLATION
#include <asm/pti.h>
#else
static inline void pti_init(void) { }
static inline void pti_finalize(void) { }
#endif

#endif
