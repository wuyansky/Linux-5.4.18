// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (c) 2012, NVIDIA CORPORATION.  All rights reserved.
 */

#include <linux/acpi.h>
#include <linux/init.h>
#include <linux/of.h>
#include <linux/clocksource.h>

extern struct of_device_id __timer_of_table[];  /* kernel image里的一个段。这个段由 TIMER_OF_DECLARE() 建立。奇怪的是，没有找到__timer_of_table的定义 */

static const struct of_device_id __timer_of_table_sentinel
	__used __section(__timer_of_table_end);

void __init timer_probe(void)
{	/* 将设备树里的Timer与驱动里注册的Timer进行匹配，对匹配到的Timer进行初始化（调用驱动里注册的初始化函数） */
	struct device_node *np;
	const struct of_device_id *match;
	of_init_fn_1_ret init_func_ret;
	unsigned timers = 0;
	int ret;

	for_each_matching_node_and_match(np, __timer_of_table, &match) {  /* 遍历驱动里注册的所有Timer */
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

	timers += acpi_probe_device_table(timer);

	if (!timers)
		pr_crit("%s: no matching timers found\n", __func__);
}
