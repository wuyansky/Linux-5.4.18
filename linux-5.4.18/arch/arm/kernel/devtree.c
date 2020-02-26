// SPDX-License-Identifier: GPL-2.0-only
/*
 *  linux/arch/arm/kernel/devtree.c
 *
 *  Copyright (C) 2009 Canonical Ltd. <jeremy.kerr@canonical.com>
 */

#include <linux/init.h>
#include <linux/export.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/memblock.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_irq.h>
#include <linux/of_platform.h>
#include <linux/smp.h>

#include <asm/cputype.h>
#include <asm/setup.h>
#include <asm/page.h>
#include <asm/prom.h>
#include <asm/smp_plat.h>
#include <asm/mach/arch.h>
#include <asm/mach-types.h>


#ifdef CONFIG_SMP
extern struct of_cpu_method __cpu_method_of_table[];

static const struct of_cpu_method __cpu_method_of_table_sentinel
	__used __section(__cpu_method_of_table_end);


static int __init set_smp_ops_by_method(struct device_node *node)
{
	const char *method;
	struct of_cpu_method *m = __cpu_method_of_table;

	if (of_property_read_string(node, "enable-method", &method))
		return 0;

	for (; m->method; m++)
		if (!strcmp(m->method, method)) {
			smp_set_ops(m->ops);
			return 1;
		}

	return 0;
}
#else
static inline int set_smp_ops_by_method(struct device_node *node)
{
	return 1;
}
#endif


/*
 * arm_dt_init_cpu_maps - Function retrieves cpu nodes from the device tree
 * and builds the cpu logical map array containing MPIDR values related to
 * logical cpus
 *
 * Updates the cpu possible mask with the number of parsed cpu nodes
 */
void __init arm_dt_init_cpu_maps(void)
{	/* 遍历"/cpus"节点，处理其逻辑 */
	/*
	 * Temp logical map is initialized with UINT_MAX values that are
	 * considered invalid logical map entries since the logical map must
	 * contain a list of MPIDR[23:0] values where MPIDR[31:24] must
	 * read as 0.
	 */
	struct device_node *cpu, *cpus;
	int found_method = 0;
	u32 i, j, cpuidx = 1;
	u32 mpidr = is_smp() ? read_cpuid_mpidr() & MPIDR_HWID_BITMASK : 0;

	u32 tmp_map[NR_CPUS] = { [0 ... NR_CPUS-1] = MPIDR_INVALID };
	bool bootcpu_valid = false;
	cpus = of_find_node_by_path("/cpus");

	if (!cpus)
		return;

	for_each_of_cpu_node(cpu) {
		const __be32 *cell;
		int prop_bytes;
		u32 hwid;

		pr_debug(" * %pOF...\n", cpu);
		/*
		 * A device tree containing CPU nodes with missing "reg"
		 * properties is considered invalid to build the
		 * cpu_logical_map.
		 */
		cell = of_get_property(cpu, "reg", &prop_bytes);
		if (!cell || prop_bytes < sizeof(*cell)) {
			pr_debug(" * %pOF missing reg property\n", cpu);
			of_node_put(cpu);
			return;
		}

		/*
		 * Bits n:24 must be set to 0 in the DT since the reg property
		 * defines the MPIDR[23:0].
		 */
		do {
			hwid = be32_to_cpu(*cell++);
			prop_bytes -= sizeof(*cell);
		} while (!hwid && prop_bytes > 0);

		if (prop_bytes || (hwid & ~MPIDR_HWID_BITMASK)) {
			of_node_put(cpu);
			return;
		}

		/*
		 * Duplicate MPIDRs are a recipe for disaster.
		 * Scan all initialized entries and check for
		 * duplicates. If any is found just bail out.
		 * temp values were initialized to UINT_MAX
		 * to avoid matching valid MPIDR[23:0] values.
		 */
		for (j = 0; j < cpuidx; j++)
			if (WARN(tmp_map[j] == hwid,
				 "Duplicate /cpu reg properties in the DT\n")) {
				of_node_put(cpu);
				return;
			}

		/*
		 * Build a stashed array of MPIDR values. Numbering scheme
		 * requires that if detected the boot CPU must be assigned
		 * logical id 0. Other CPUs get sequential indexes starting
		 * from 1. If a CPU node with a reg property matching the
		 * boot CPU MPIDR is detected, this is recorded so that the
		 * logical map built from DT is validated and can be used
		 * to override the map created in smp_setup_processor_id().
		 */
		if (hwid == mpidr) {
			i = 0;
			bootcpu_valid = true;
		} else {
			i = cpuidx++;
		}

		if (WARN(cpuidx > nr_cpu_ids, "DT /cpu %u nodes greater than "
					       "max cores %u, capping them\n",
					       cpuidx, nr_cpu_ids)) {
			cpuidx = nr_cpu_ids;
			of_node_put(cpu);
			break;
		}

		tmp_map[i] = hwid;

		if (!found_method)
			found_method = set_smp_ops_by_method(cpu);
	}

	/*
	 * Fallback to an enable-method in the cpus node if nothing found in
	 * a cpu node.
	 */
	if (!found_method)
		set_smp_ops_by_method(cpus);

	if (!bootcpu_valid) {
		pr_warn("DT missing boot CPU MPIDR[23:0], fall back to default cpu_logical_map\n");
		return;
	}

	/*
	 * Since the boot CPU node contains proper data, and all nodes have
	 * a reg property, the DT CPU list can be considered valid and the
	 * logical map created in smp_setup_processor_id() can be overridden
	 */
	for (i = 0; i < cpuidx; i++) {
		set_cpu_possible(i, true);
		cpu_logical_map(i) = tmp_map[i];
		pr_debug("cpu logical map 0x%x\n", cpu_logical_map(i));
	}
}

bool arch_match_cpu_phys_id(int cpu, u64 phys_id)
{
	return phys_id == cpu_logical_map(cpu);
}

static const void * __init arch_get_next_mach(const char *const **match)
{	/* 功能：针对C代码注册struct machine_desc[]，获取其各个元素的.dt_compat属性值，通过参数match传出。每调用一次本函数，就向后迭代一次。返回：当前struct machine_desc的指针 */
	static const struct machine_desc *mdesc = __arch_info_begin;
	const struct machine_desc *m = mdesc;

	if (m >= __arch_info_end)
		return NULL;

	mdesc++;
	*match = m->dt_compat;
	return m;
}

/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
const struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)  /* dt_phys：二进制的设备树的（物理）起始地址 */
{	/* 功能：匹配machine的"compatible"属性，顺便从设备树里获取内核命令行、"#size-cells"和"#address-cells"以及内存信息，并将其保存到全局变量或注册到系统里。返回：匹配成功返回struct machine_desc的指针；失败返回NULL */
	const struct machine_desc *mdesc, *mdesc_best = NULL;

#if defined(CONFIG_ARCH_MULTIPLATFORM) || defined(CONFIG_ARM_SINGLE_ARMV7M)  /* 对于ARM(64)平台，这段代码无效 */
	DT_MACHINE_START(GENERIC_DT, "Generic DT based system")
		.l2c_aux_val = 0x0,
		.l2c_aux_mask = ~0x0,
	MACHINE_END

	mdesc_best = &__mach_desc_GENERIC_DT;
#endif

	if (!dt_phys || !early_init_dt_verify(phys_to_virt(dt_phys)))
		return NULL;

	mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach);  /* 将C代码注册的machine与设备树根节点下的"compatible"属性进行匹配，得到最佳匹配，然后返回其struct machine_desc的指针 */

	if (!mdesc) {  /* 匹配失败，则打印出错误信息 */
		const char *prop;
		int size;
		unsigned long dt_root;

		early_print("\nError: unrecognized/unsupported "
			    "device tree compatible list:\n[ ");

		dt_root = of_get_flat_dt_root();
		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);
		while (size > 0) {
			early_print("'%s' ", prop);
			size -= strlen(prop) + 1;
			prop += strlen(prop) + 1;
		}
		early_print("]\n\n");

		dump_machine_table(); /* does not return */
	}

	/* We really don't want to do this, but sometimes firmware provides buggy data */
	if (mdesc->dt_fixup)
		mdesc->dt_fixup();

	early_init_dt_scan_nodes();  /* 从设备树里获取内核命令行、"#size-cells"和"#address-cells"以及可用的内存信息，并将其保存到全局变量或注册到系统里 */

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc->nr;

	return mdesc;
}
