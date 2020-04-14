// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2020, Linaro Limited
 */
#include <compiler.h>
#include <kernel/generic_boot.h>
#include <mm/core_mmu.h>

unsigned long __section(".text.dummy.get_aslr_seed")
get_aslr_seed(void *fdt __unused)
{
	return 0;
}

void __section(".text.dummy.core_init_mmu_map")
core_init_mmu_map(unsigned long seed __unused,
		  struct core_mmu_config *cfg __unused)
{
}

void __section(".text.dummy.generic_boot_init_primary")
generic_boot_init_primary(unsigned long pageable_part __unused,
                          unsigned long nsec_entry __unused,
                          unsigned long fdt __unused,
                          unsigned long dcak_b __unused,
                          size_t dc_l __unused,
                          size_t ak_l __unused)
{
}
