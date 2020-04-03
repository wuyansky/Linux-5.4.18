// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/clocksource.h>

extern struct of_device_id __timer_of_table[];  /* kernel image里的一个段。这个段由 TIMER_OF_DECLARE() 建立 */

static const struct of_device_id __timer_of_table_sentinel  /* 未使用，不关心 */
	__used __section(__timer_of_table_end);

void __init timer_probe(void)
{	/* 将设备树里的Timer与驱动里注册的Timer进行交叉匹配，调用驱动里注册的初始化函数，对匹配到的Timer进行初始化 */
	struct device_node *np;
	const struct of_device_id *match;
	of_init_fn_1_ret init_func_ret;
	unsigned timers = 0;
	int ret;

	for_each_matching_node_and_match(np, __timer_of_table, &match) {  /* 将设备树里的Timer与驱动里注册的Timer进行交叉匹配。每匹配到一个元素，则拿到其在驱动里注册的struct of_device_id实体match，以及对应的设备树节点np */
		if (!of_device_is_available(np))
			continue;

		init_func_ret = match->data;  /* 取出驱动里注册的初始化函数（TIMER_OF_DECLARE()的最后一个参数） */

		ret = init_func_ret(np);  /* 调用该初始化函数 */
		if (ret) {
			if (ret != -EPROBE_DEFER)
				pr_err("Failed to initialize '%pOF': %d\n", np,
				       ret);
			continue;
		}

		timers++;
	}

	timers += acpi_probe_device_table(timer);  /* 不关心 */

	if (!timers)
		pr_crit("%s: no matching timers found\n", __func__);
}
