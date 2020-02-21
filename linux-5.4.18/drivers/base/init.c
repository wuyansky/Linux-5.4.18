// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2002-3 Patrick Mochel
 * Copyright (c) 2002-3 Open Source Development Labs
 */

#include <linux/device.h>
#include <linux/init.h>
#include <linux/memory.h>
#include <linux/of.h>

#include "base.h"

/**
 * driver_init - initialize driver model.
 *
 * Call the driver model init functions to initialize their
 * subsystems. Called early from init/main.c.
 */
void __init driver_init(void)
{
	/* These are the core pieces */
	devtmpfs_init();	/* devtmpfs初始化。非重点 */
	devices_init();		/* sysfs里"devices"相关的初始化。非重点 */
	buses_init();		/* sysfs里"bus"和"system"相关的初始化。非重点 */
	classes_init();		/* sysfs里"class"相关的初始化。非重点 */
	firmware_init();	/* sysfs里"firmware"相关的初始化。非重点 */
	hypervisor_init();	/* sysfs里"hypervisor"相关的初始化。非重点 */

	/* These are also core pieces, but must come after the
	 * core core pieces.
	 */
	of_core_init();		/* 向sysfs和procfs里添加"devicetree"目录项 */
	platform_bus_init();	/* ***重点*** platform总线初始化，匹配设备与驱动，执行probe() */
	cpu_dev_init();		/* 在sysfs里支持CPU设备 */
	memory_dev_init();	/* 在sysfs里支持内存设备 */
	container_dev_init();	/* 注册/sys/devices/system/container */
}
