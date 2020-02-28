# Linux kernel启动过程学习笔记

作者：武彦
文档版本：V0.1
修改日期：2020-02-25


[TOC]


# 1. 背景
Linux的整个启动过程可以分为如下三个阶段：
（1）bootloader（U-Boot）引导阶段
（2）kernel启动阶段
（3）用户空间程序启动阶段
这篇文章里，我们仅讲解第二阶段。
与本文对应的内核版本为Linux 5.4.18。
我们只关心ARM平台的初始化过程，其他平台的代码直接跳过。
# 2. 学习方法
内核启动代码不仅数量庞大而且异常复杂。其中涉及的体系结构知识、C语言高级用法以及各种奇奇怪怪的编译器修饰语，都会成为我们读代码的障碍。
我们可以从两方面来克服这些障碍：
* 抓住核心脉络：在读代码的过程中，时刻牢记我们的目标是要形成对于启动过程的知识框架，而不是搞清楚每一个细节。这样一来，我们便不会在漫无边际的丛林里迷路。抓住脉络要求我们分清主次，比如与ARM体系结构相关的代码就是我们要分析的重点，而与ARM无关的（比如UEFI）或者极少使用的功能（比如initrd），就可以直接跳过。再比如，启动过程中有很多与安全、鉴权、加密相关的初始化工作，这些也不是我们现阶段的重点，大致了解即可，无需深入分析。
* 理清关键细节：内核代码建立在无数的细节之上，其中一些细节对于我们理解实现原理和设计意图、建立脉络是十分有用的。我们要把这些关键细节彻底吃透。典型的关键细节如setup_machine()的实现、initcall的执行过程、内核命令行的解析过程等。
# 3. 函数概览
启动过程中，在u-boot做完必要的硬件初始化工作以后，会将kernel image加载到内存并解压，然后跳转到内核代码```init/main.c: start_kernel()```开始执行。
start_kernel()函数的原型如下：
```C
asmlinkage __visible void __init start_kernel(void);
```
内核启动的全部工作都在这一个函数里完成。因此，我们只分析这一个函数就够了。
我们先来鸟瞰一下它的整体面貌：
```C
asmlinkage __visible void __init start_kernel(void)
{
	char *command_line;
	char *after_dashes;

	set_task_stack_end_magic(&init_task);  /* 在栈底设置魔数，以便检查栈是否损坏。init_task的定义：init/init_task.c line 56，它是0号进程。它会创建出1号进程（init）和2号进程（kthreadd），然后自己退化成IDLE进程 */
	smp_setup_processor_id();  /* 针对SMP处理器。见 arch/arm(64)/kernel/setup.c */
	debug_objects_early_init();  /* defined in lib/debugobjects.c */

	cgroup_init_early();

	local_irq_disable();
	early_boot_irqs_disabled = true;  /* defined in this file Line118. This flag is cleared in current function Line703  */

	/*
	 * Interrupts are still disabled. Do necessary setups, then
	 * enable them.
	 */
	boot_cpu_init();  /* Activate the first processor */
	page_address_init();  /* mm/highmem.c */
	pr_notice("%s", linux_banner);	/* 打印内核版本信息，内核启动的第一行信息就来自这里 */
	early_security_init();
	setup_arch(&command_line);  /* 体系架构相关的初始化，包括内核命令行、设备树、内存等。**重要** */
	setup_command_line(command_line);  /* 将command_line备份到其他多个全局变量里 */
	setup_nr_cpu_ids();  /* 为全局变量nr_cpu_ids赋值。其值为硬件CPU数目，注意不是online CPU数目 */
	setup_per_cpu_areas();  /* 为per CPU变量预留空间。多核下，arm架构 mm/percpu.c:2960，arm64架构 mm/percpu.c:2960 或 /arch/arm64/mm/numa.c:140 */
	smp_prepare_boot_cpu();	/* arch-specific boot-cpu hooks */
	boot_cpu_hotplug_init();

	build_all_zonelists(NULL);
	page_alloc_init();

	pr_notice("Kernel command line: %s\n", boot_command_line);
	/* parameters may set static keys */
	jump_label_init();  /* 性能优化相关，无需关心 */
	parse_early_param();  /* 解析并执行boot_command_line里的early param。这个函数在arch/arm/kernel/setup.c: setup_arch()里被调用过了，因此这里什么也不会做 */
	after_dashes = parse_args("Booting kernel",  /* 此函数解析到"--"即停止 */
				  static_command_line, __start___param,  /* 解析static_command_line，匹配__start___param[]里的参数名；若匹配失败，则执行unknown_bootoption() */
				  __stop___param - __start___param,  /* __start___param和__stop___param都是elf里的段 */
				  -1, -1, NULL, &unknown_bootoption);
	if (!IS_ERR_OR_NULL(after_dashes))  /* "--"之后还有内容。这些内容作为参数传递给init进程 */
		parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,  /* 解析"--"之后的内容 */
			   NULL, set_init_arg);  /* 执行set_init_arg() */

	/*
	 * These use large bootmem allocations and must precede
	 * kmem_cache_init()
	 */
	setup_log_buf(0);
	vfs_caches_init_early();  /* 初始化VFS（虚拟文件系统）所需的缓存（dcache、inode等） */
	sort_main_extable();  /* 对内核内置的exception table进行排序 */
	trap_init();  /* 空函数 */
	mm_init();  /* init/main.c: Line549。内存初始化。启动过程中的内存信息来自这里 */

	ftrace_init();  /* ftrace是用于内核故障调试和性能分析的工具。暂不关心 */

	/* trace_printk can be enabled here */
	early_trace_init();  /* 调试相关 */

	/*
	 * Set up the scheduler prior starting any interrupts (such as the
	 * timer interrupt). Full topology setup happens at smp_init()
	 * time - but meanwhile we still have a functioning scheduler.
	 */
	sched_init();  /* 调度器初始化 */
	/*
	 * Disable preemption - early bootup scheduling is extremely
	 * fragile until we cpu_idle() for the first time.
	 */
	preempt_disable();  /* 关抢占 */
	if (WARN(!irqs_disabled(),  /* 如果中断被误开启了 */
		 "Interrupts were enabled *very* early, fixing it\n"))
		local_irq_disable();  /* 则强制关闭它 */
	radix_tree_init();  /* 不管它 */

	/*
	 * Set up housekeeping before setting up workqueues to allow the unbound
	 * workqueue to take non-housekeeping into account.
	 */
	housekeeping_init();

	/*
	 * Allow workqueue creation and work item queueing/cancelling
	 * early.  Work item execution depends on kthreads and starts after
	 * workqueue_init().
	 */
	workqueue_init_early();  /* 工作队列的早期初始化。不关心 */

	rcu_init();  /* RCU初始化。不关心 */

	/* Trace events are available after this */
	trace_init();  /* 跟踪事件初始化。不关心 */

	if (initcall_debug)
		initcall_debug_enable();  /* 调试相关。不关心 */

	context_tracking_init();  /* 不关心 */
	/* init some links before init_ISA_irqs() */
	early_irq_init();
	init_IRQ();			/* 初始化中断控制器 */
	tick_init(); 
	rcu_init_nohz();
	init_timers();		/* 下面这4个函数是软中断和内核时钟机制初始化 */
	hrtimers_init();
	softirq_init();	
	timekeeping_init();	/* 初始化系统时钟计时。在此之前，所有的时间戳都是零 */

	/* 这一段都是与随机数和熵相关的代码。与体系架构关心不大，无需关心。
	 * For best initial stack canary（金丝雀，这里是“预警”的意思） entropy（熵）, prepare it after:
	 * - setup_arch() for any UEFI RNG entropy and boot cmdline access
	 * - timekeeping_init() for ktime entropy used in rand_initialize()
	 * - rand_initialize() to get any arch-specific entropy like RDRAND
	 * - add_latent_entropy() to get any latent entropy
	 * - adding command line entropy
	 */
	rand_initialize();
	add_latent_entropy();
	add_device_randomness(command_line, strlen(command_line));
	boot_init_stack_canary();  /* 初始化栈canary值，canary是用于防止栈溢出攻击的保护字 */

	time_init();  /* 初始化Clock和Timer */
	printk_safe_init();	/* 针对多核下的printk的初始化，无需关心 */
	perf_event_init();	/* 没看懂 */
	profile_init();		/* profile是内核诊断工具 */
	call_function_init();	/* 没看懂 */
	WARN(!irqs_disabled(), "Interrupts were enabled early\n");

	early_boot_irqs_disabled = false;  /* This flag was set earlier in current function (Line588) */
	local_irq_enable();

	kmem_cache_init_late();  /* cache相关 */

	/*
	 * HACK ALERT! This is early. We're enabling the console before
	 * we've done PCI setups etc, and console_init() must be aware of
	 * this. But we do want output early, in case something goes wrong.
	 */
	console_init();  /* console初始化。自此以后就可以使用printk()了。非重点，不关心。PS：其实在此前是有printk的，但其打印的内容必须在console_init之后才能打印出来，也就是说之前prinkt的数据都保存在了一个缓冲区内，等到console_init以后才打印出来 */
	if (panic_later)
		panic("Too many boot %s vars at `%s'", panic_later,
		      panic_param);

	lockdep_init();	/* Lockdep是内核检测deadlock的手段。对应的配置项为CONFIG_LOCKDEP，默认没有开启。非重点，不关心 */

	/*
	 * Need to run this when irqs are enabled, because it wants
	 * to self-test [hard/soft]-irqs on/off lock inversion bugs
	 * too:
	 */
	locking_selftest();  /* 锁的自测。无需关心 */

	/*
	 * This needs to be called before any devices perform DMA
	 * operations that might use the SWIOTLB bounce buffers. It will
	 * mark the bounce buffers as decrypted so that their usage will
	 * not cause "plain-text" data to be decrypted when accessed.
	 */
	mem_encrypt_init();  /* 空函数 */

#ifdef CONFIG_BLK_DEV_INITRD  /* initrd相关。暂不关心 */
	if (initrd_start && !initrd_below_start_ok &&
	    page_to_pfn(virt_to_page((void *)initrd_start)) < min_low_pfn) {
		pr_crit("initrd overwritten (0x%08lx < 0x%08lx) - disabling it.\n",
		    page_to_pfn(virt_to_page((void *)initrd_start)),
		    min_low_pfn);
		initrd_start = 0;
	}
#endif
	setup_per_cpu_pageset();  /* 没看懂 */
	numa_policy_init();  /* NUMA (Non-Uniform Memory Access Architecture) 初始化。SMP与服务器并行相关，与我们无关 */
	acpi_early_init();  /* ACPI (Advanced Configuration and Power Management Interface)，高级配置和电源管理接口。x86平台上的东西，与ARM无关 */
	if (late_time_init)
		late_time_init();  /* 其实就是执行了 arch/arm/kernel/smp_twd.c: twd_timer_setup()。Timer初始化相关，暂不深究 */
	sched_clock_init();	/* 初始化调度时钟。没细看 */
	calibrate_delay();	/* 对忙等的精度进行校准，得到全局变量 loops_per_jiffy */
	pid_idr_init();  /* idr即"ID Radix"，内核中通过radix树对ID进行组织和管理，是一种将整数ID和指针关联在一起的一种机制。不关心 */
	anon_vma_init(); /* 匿名虚拟内存域初始化。暂不深究 */
#ifdef CONFIG_X86  /* 不关心 */
	if (efi_enabled(EFI_RUNTIME_SERVICES))
		efi_enter_virtual_mode();
#endif
	thread_stack_cache_init();  /* 不关心 */
	cred_init();	/* 信任证书初始化。不关心 */
	fork_init();	/* fork机制初始化。不关心 */
	proc_caches_init();	/* 进程创建相关。不关心 */
	uts_ns_init();	/* UTS (UNIX Time-sharing System namespace) 提供了主机名和域名的隔离。能够使得子进程有独立的主机名和域名(hostname)，这一特性在Docker容器技术中被用到。不关心 */
	buffer_init();	/* 缓存系统初始化。不关心 */
	key_init();		/* 内核密钥管理系统初始化。不关心 */
	security_init();	/* 安全框架初始化。不关心 */
	dbg_late_init();	/* 内核调试工具（kgdb、kdb）初始化。不关心 */
	vfs_caches_init();	/* VFS的缓存初始化。See also Line625。不关心 */
	pagecache_init();	/* 文件page cache初始化。不关心 */
	signals_init();		/* 信号机制初始化。不关心 */
	seq_file_init();	/* Seq file初始化。不关心 */
	proc_root_init();	/* proc文件系统初始化。不关心 */
	nsfs_init();	/* NSFS (Name Space File System) 初始化。不关心 */
	cpuset_init();	/* 初始化cpuset。不关心 */
	cgroup_init();	/* 初始化cgroup。不关心 */
	taskstats_init_early();	/* 初始化taskstats（用于向用户空间导出各个任务的统计信息）。不关心 */
	delayacct_init();	/* 初始化delayacct（per-task delay accounting）。不关心 */

	poking_init();	/* 空函数 */
	check_bugs();	/* arch/arm/kernel/bugs.c。检查是否有bug。不关心  */

	acpi_subsystem_init();	/* ACPI相关。不关心 */
	arch_post_acpi_subsys_init();	/* ACPI相关。不关心 */
	sfi_init_late();  /* SFI (Simple Firmware Interface) 初始化。不关心 */

	/* Do the rest non-__init'ed, we're now alive */
	arch_call_rest_init();	/* 初始化剩余部分 ***重要*** */
}
```
怎么样，是不是长得令人发指？
不要慌，再复杂它也是人写出来的，多花点功夫总能看懂。
接下来，我们从头到尾、抽丝剥茧，一层一层来分析这个函数。
# 4. 代码详解
## 4.1 init_task
先来看start_kernel()的第一句：
```C
set_task_stack_end_magic(&init_task);
```
这里在init_task任务的栈底设置了一个魔数（STACK_END_MAGIC，其值为0x57AC6E9D），以便后续可以检查启动过程中栈是否有损坏（@TODO: 在哪检查的？）。这属于调试与异常处理的功能，我们暂不关心。
需要注意的是，这里出现了一个```task_struct```型的全局变量```init_task```。我们知道task_struct是内核用来描述一个任务（或称线程）的结构体。那么，这个init_task是从哪里来的，又是做什么的呢？
我们可以在init/init_task.c里找到init_task的定义。而它又是被谁运行的呢？
其实它是被汇编代码运行起来的。也就是说，当我们进入start_kernel()以后，其实就已经处于init_task的上下文里了，或者说，start_kernel()就是运行中的init_task。
再拓展一点：init_task是Linux的0号任务（或称线程，后文不再区分），它是所有内核任务以及用户任务的祖先。它会创建出1号进程（init）和2号进程（kthreadd），然后自己退化成IDLE进程。
在内核代码里，从start_kernel()的最开头直到最后一句（准确地说，是在arch_call_rest_init()创造出1号、2号任务之前），在这段时间内，系统内都只有init_task这一个任务在运行。
参考：
[linux init_task的初始化](https://blog.csdn.net/shenjiang11/article/details/62883965)
## 4.2 smp_setup_processor_id()
接着看start_kernel()的第二句：
```C
smp_setup_processor_id();
```
它与SMP（多核）有关。做了一些与多核相关的初始化工作（@TODO：具体是什么工作？不太懂），但是并没有真正把多核并行地跑起来。也就是说，我们仍在单核上运行。
在这个函数的末尾，使用了pr_info()打印"Booting Linux on physical CPU 0x%x\n"。这是我们内核出生后的的第一声啼哭（第一句打印）。但需要说明的是，这句话不会立即被打印出来。这是因为pr_info()调用了printk()，而此时printk()所需的功能还没有被初始化。因此，这句话只是把要打印的字符串放在了log buffer里，等待输出。
## 4.3 debug_objects_early_init()
接下来是这一句：
```C
debug_objects_early_init();
```
初始化用于调试的debug_objects。非重点。
## 4.4 cgroup_init_early()
接下来是这一句：
```C
cgroup_init_early();
```
初始化用于实现进程管理的cgroup。非重点。

## 4.5 中断的关闭与开启
接下来是如下两句：
```C
local_irq_disable();
early_boot_irqs_disabled = true;
```
这里关了全局中断，并置全局变量early_boot_irqs_disabled为true。
如果我们继续往下看start_kernel()的话，会看到与之对应的两句代码：
```C
early_boot_irqs_disabled = false;
local_irq_enable();
```
也就是说，在这两段代码之间，是没有中断存在的。而在4.1中我们知道当前系统里只有一个任务在运行，于是就不存在并发或抢占的情形了。如此一来，运行环境就变得很单纯了，这使得我们分析代码也容易了很多。
## 4.6 boot_cpu_init()
```C
boot_cpu_init();
```
它将当前用到的CPU标记为"online","active","present"等。非重点。
## 4.7 page_address_init()
```C
page_address_init();
```
这是内存页相关的初始化（@TODO：待确认）。非重点。
## 4.8 打印linux_banner
```C
pr_notice("%s", linux_banner);
```
在这里打印出内核的简要信息，如下：
```C
const char linux_banner[] =
	"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
	LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";
```
与4.2中提到的打印功能一样，这里的打印也只是将字符串暂存起来，等log buffer完成初始化之后，再一并输出。
## 4.9 early_security_init()
```C
early_security_init();
```
安全机制的早期初始化。非重点。
## 4.10 setup_arch()
```C
setup_arch(&command_line);
```
终于来到我们的第一个重点函数了！
setup_arch()是一个非常长的函数，它主要完成体系架构相关的初始化，包括内核命令行、设备树、内存等。
首先来看下它的样貌：
```C
void __init setup_arch(char **cmdline_p)
{
	const struct machine_desc *mdesc;

	setup_processor();
	mdesc = setup_machine_fdt(__atags_pointer);
	if (!mdesc)  /* 匹配失败 */
		...  /* 尝试旧的内核传参机制（ATAGS）。无需关注 */
		... /* 若设备树和ATAGS都无效，则报错 */
	}
	machine_desc = mdesc;  /* 备份到全局变量里 */
	machine_name = mdesc->name;  /* 如"ARM" */
	...
	if (mdesc->reboot_mode != REBOOT_HARD)
		reboot_mode = mdesc->reboot_mode;  /* 备份到全局变量里 */
	...  /* 初始化全局变量init_mm */
	/* populate cmd_line too for later use, preserving boot_command_line */
	strlcpy(cmd_line, boot_command_line, COMMAND_LINE_SIZE);  /* 将内核命令行备份到全局变量cmd_line[]里 */
	*cmdline_p = cmd_line;  /* 给传出参数赋值 */

	early_fixmap_init();
	early_ioremap_init();

	parse_early_param();	/* 解析并执行boot_command_line里的early param */

#ifdef CONFIG_MMU
	early_mm_init(mdesc);
#endif
	setup_dma_zone(mdesc);	/* 给全局变量 arm_dma_zone_size, arm_dma_limit, arm_dma_pfn_limit赋值   */
	...
	/*
	 * Make sure the calculation for lowmem/highmem is set appropriately
	 * before reserving/allocating any mmeory
	 */
	adjust_lowmem_bounds();  /* arch/arm/mm/mmu.c */
	arm_memblock_init(mdesc);  /* 初始化内存 */
	/* Memory may have been removed so recalculate the bounds. */
	adjust_lowmem_bounds();

	early_ioremap_reset();

	paging_init(mdesc);  /* 建立页表，初始化memory zone */
	request_standard_resources(mdesc);  /* 为内核代码段、内核数据段、显存等申请内存空间 */

	if (mdesc->restart)
		arm_pm_restart = mdesc->restart;

	unflatten_device_tree();  /* 将DTB展开为struct device_node型的数据结构 */

	arm_dt_init_cpu_maps();   /* 处理"/cpus"节点 */
	...
#ifdef CONFIG_SMP  /* 多核的初始化，暂不深究 */
	...
	smp_init_cpus();
	...
#endif
	...
#ifdef CONFIG_GENERIC_IRQ_MULTI_HANDLER  /* 暂不关心 */
	handle_arch_irq = mdesc->handle_irq;
#endif
	...
	if (mdesc->init_early)
		mdesc->init_early();
}
```
虽然函数很长，但是要做的事情还是比较清晰的。我们就不再一行一行展开细说了。遵照文章开头讲到的学习方法：先叙述脉络，再解释关键函数。
### 4.10.1 脉络
在setup_arch()里，首先使用```setup_processor()```来检测处理器类型、初始化处理器相关的底层变量，并打印出处理器的型号等信息。
接着，调用```setup_machine_fdt()```来对设备树进行初步的解析，匹配C代码里注册的machine，并返回对应的machine描述符，即```struct machine_desc *mdesc```，后续对machine的操作都以此描述符为句柄。
接下来，对内存、DMA zone、页表、内核代码段、内核数据段、显存等存储空间都进行了初始化。这部分是重点也是难点。
然后，使用```unflatten_device_tree()```，将DTB展开为struct device_node型的数据结构，供设备驱动使用。
最后，对多核进行初始化。
另外，还将内核里最终生效的命令行```boot_command_line```通过```setup_arch(&command_line);```的```command_line```参数传出，供调用方使用。
### 4.10.2 关键函数
#### 4.10.2.1 setup_machine_fdt()
此函数的参数为设备树Blob（即二进制的、未展开的DTB镜像）在内存中的物理地址。可以看到调用方给它传递了全局变量```__atags_pointer```，而__atags_pointer正是设备树在内存里的物理地址。__atags_pointer对应CPU寄存器R1的值，见arch/arm/kernel/head-common.S: .long __machine_arch_type @ r1。
这个函数的脉络如下：
```C
/**
 * setup_machine_fdt - Machine setup when an dtb was passed to the kernel
 * @dt_phys: physical address of dt blob
 *
 * If a dtb was passed to the kernel in r2, then use it to choose the
 * correct machine_desc and to setup the system.
 */
 /**
 * 功能：匹配machine的"compatible"属性，顺便从设备树里获取内核命令行、"#size-cells"和"#address-cells"以及内存信息，并将其保存到全局变量或注册到系统里。
 * 参数：dt_phys：二进制的设备树的（物理）起始地址
 * 返回：匹配成功返回struct machine_desc的指针；失败返回NULL
 */
const struct machine_desc * __init setup_machine_fdt(unsigned int dt_phys)
{
	const struct machine_desc *mdesc, *mdesc_best = NULL;
	...
	mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach); 
	if (!mdesc) {  /* 匹配失败 */
		...   /* 打印出错误信息 */
		...   /* does not return */
	}
	/* We really don't want to do this, but sometimes firmware provides buggy data */
	if (mdesc->dt_fixup)
		mdesc->dt_fixup();

	early_init_dt_scan_nodes();

	/* Change machine number to match the mdesc we're using */
	__machine_arch_type = mdesc->nr;

	return mdesc;
}
```
这里最重要的一条语句就是```mdesc = of_flat_dt_match_machine(mdesc_best, arch_get_next_mach);```。我们先对它进行分析。
#### 4.10.2.1.1 of_flat_dt_match_machine()
原型：
```C
const void * __init of_flat_dt_match_machine(const void *default_match,
		const void * (*get_next_compat)(const char * const**))
```
这个函数的作用是将C代码里注册的machine的.dt_compat属性与设备树根节点下的"compatible"属性进行匹配，返回匹配的struct machine_desc的指针。
其第一个参数```default_match```，用作函数的默认返回值。也就是在匹配失败的情况下返回它。实际上，在我们的ARM平台上，多数情况下mdesc_best的值为NULL。
第二个参数```get_next_compat```是个函数指针，用于获取驱动里注册的machine的指针和其.dt_compat成员的值。
我们知道，在内核C代码里会使用MACHINE_START()或DT_MACHINE_START()和MACHINE_END宏来定义一个个的struct machine_desc型全局变量。事实上，这些变量都被放到了kernel镜像的一个特殊段里（详见DT_MACHINE_START()的定义），从而形成了一个结构体数组。
of_flat_dt_match_machine()调用get_next_compat函数（其值为arch_get_next_mach）对这些结构体分别进行解析，取出其.dt_compat成员（字符串），并与设备树里根节点下的"compatible"值（可能有多个值）进行匹配，匹配度最高的那个struct machine_desc变量的指针就作为幸运儿，被返回到调用方了。
在setup_machine_fdt()里，还有一个比较重要的函数：early_init_dt_scan_nodes()。我们接下来对它进行简要分析。
#### 4.10.2.1.2 early_init_dt_scan_nodes()
这个函数的功能可以总结为三点：
* 获取最终生效的命令行参数（可能来自设备树、U-Boot或kernel自身，取决于内核的配置项CONFIG_CMDLINE_XXX），将其填充到全局变量boot_command_line[]里，以便后续对其进行解析。
* 获取设备树顶层的"#size-cells"和"#address-cells"的值，放到全局变量dt_root_size_cells和dt_root_addr_cells里。若没有匹配到对应节点，则使用默认值（均为1）。
* 从设备树里解析可用的物理内存信息（不含保留内存），并将这些内存注册到系统里。如果设备树里声明了某段内存为"hotpluggable"，也会进行相应的处理。
#### 4.10.2.2 parse_early_param()
parse_early_param()首先对内核的命令行boot_command_line进行备份，接着使用parse_early_options()对备份进行解析。这样可以避免对boot_command_line的更改。
最终其实执行的逻辑其实很简单: 遍历cmdline，解析出每一组键值对(param, val)，然后执行 do_early_param(param, val, "early options", NULL)。
```C
/* Check for early params. */
static int __init do_early_param(char *param, char *val,  /* param和val是解析CMDLINE得到的一队参数名和参数值。比如CMDLINE中包含"console=ttyS0,115200"，则解析到此语句时，param为"console"，val为"ttyS0,115200" */
				 const char *unused, void *arg)  /* 这两个参数都没用 */
{
	const struct obs_kernel_param *p;

	for (p = __setup_start; p < __setup_end; p++) {  /* 遍历elf的某个段，此段是一个struct obs_kernel_param型的数组，由__setup()或early_param()宏建立 */
		if ((p->early && parameq(param, p->str)) ||  /* 若该数组元素的early标志有效（即该数组元素是由early_param()宏生成的），且参数名等于param */
		    (strcmp(param, "console") == 0 &&  /* 用CMDLINE里的"console"去匹配驱动代码里的"earlycon"。 */
		     strcmp(p->str, "earlycon") == 0)  /* 比如CMDLINE里有"console=ttyS0,115200"，同时驱动代码里又有__setup("earlycon", xxx_func);或early_param("earlycon", xxx_func);，则执行xxx_func("ttyS0,115200")） */
		) {                                    /* 见 drivers/tty/serial/earlycon.c: Line227: early_param("earlycon", param_setup_earlycon); */
			if (p->setup_func(val) != 0)  /* 执行动作 */
				pr_warn("Malformed early option '%s'\n", param);  /* Malformed: 畸形的 */
		}
	}
	/* We accept everything at this stage. */
	return 0;
}
```
do_early_param()解析的是由early_param()这个宏所生成的结构体（struct obs_kernel_param）。这些结构体被放在kernel image中的一个单独的段里。do_early_param()将CMDLINE里的参数名param与struct obs_kernel_param的.str成员进行匹配，若匹配成功，则执行.setup_func函数，并将CMDLINE里的参数值val传递给它。
回过头来捋一下：parse_early_param()的主要作用是解析由early_param()注册的参数，并执行其注册的回调函数，以此来实现启动早期的初始化，比如early-console等。
#### 4.10.2.3 arm_memblock_init()
```C
void __init arm_memblock_init(const struct machine_desc *mdesc)
{
	/* Register the kernel text, kernel data and initrd with memblock. */
	memblock_reserve(__pa(KERNEL_START), KERNEL_END - KERNEL_START);  /* 为内核代码段预留内存 */
	arm_initrd_init();  /* 为initrd预留内存 */
	arm_mm_memblock_reserve();  /* 为页表预留内存 */
	/* reserve any platform specific memblock areas */
	if (mdesc->reserve)
		mdesc->reserve();
	early_init_fdt_reserve_self();  /* 为DTB预留内存 */
	early_init_fdt_scan_reserved_mem();  /* 从设备树里获取"/memreserve/"和"reserved-memory"所声明的保留内存，将其注册到系统里，并对其进行初始化 */
	/* reserve memory for DMA contiguous allocations */
	dma_contiguous_reserve(arm_dma_limit);
	arm_memblock_steal_permitted = false;
	memblock_dump_all();  /* 打印出已初始化的内存信息 */
}
```
这个函数非常重要，它执行内存初始化工作，包括内核代码段、initrd、页表、DTB所需的内存，以及设备树里由"/memreserve/"和"reserved-memory"所声明的保留内存，还有DMA的连续内存。
这个函数相对比较难以理解，因为它涉及很多晦涩难懂的内存layout与内存管理知识。这里我们就不展开讲了。
另外，```early_init_fdt_scan_reserved_mem()```这个函数需要重点关注下。它初始化了设备树里配置的保留内存（"/memreserve/"和"reserved-memory"）。这个函数并不难懂，有兴趣的话可以去看看源码。
#### 4.10.2.3 unflatten_device_tree()
这个函数将DTB展开为struct device_node型的数据结构，赋给全局变量```of_root```。另外，还会处理设备树里的alias节点。
执行此函数以后，我们就可以使用of_xxx这样的API对设备树进行操作了。
这里稍作了解即可，我们一般不会改动它。
以下我们仅对重点函数进行讲解，其余函数直接跳过。
## 4.11 setup_command_line()
```C
setup_command_line(command_line);
```
这个函数将command_line备份到其他多个全局变量里：```saved_command_line```，```static_command_line```。
## 4.12 parse_args()
```C
after_dashes = parse_args("Booting kernel", 
	static_command_line, __start___param, 
	__stop___param - __start___param,
	-1, -1, NULL, &unknown_bootoption);
if (!IS_ERR_OR_NULL(after_dashes))  /* 若"--"之后还有内容，则解析它们 */
	parse_args("Setting init args", after_dashes, NULL, 0, -1, -1,
	NULL, set_init_arg);
```
首先来看第一句：它解析内核命令行里要传递给内核模块的参数（module.param=val），将param与kernel image的模块参数段里的.name成员进行匹配。若匹配成功，则将val设置给此模块；否则，执行unknown_bootoption()。static_command_line是待解析的内核命令行；__start___param ~ __stop___param是kernel image里的一个段（__param）。此函数解析到"--"即停止。
由于前面解析到"--"就会停止，那么"--"之后的内容就交给```parse_args("Setting init args", after_dashes, NULL, 0, -1, -1, NULL, set_init_arg);```来解析了。这部分内容会作为稍后启动的init进程的参数（argv[]）传递给init。
这么讲解有点难懂。我们来看一个例子：
假如内核命令行中包含内容```"mymodule.num=10 -- my_argv"```，而内核模块mymodule.ko里又有```module_param(num, int, S_IRUGO);```，那么经过上面所述的解析过程，mymodule.ko里的num变量就会被赋值10；而init进程在执行的时候，会带上一个参数"my_argv"。
## 4.13 mm_init()
内存初始化。@TODO：这部分比较复杂，看不太懂。

## 4.14 init_IRQ()
初始化中断控制器。在设备树里寻找中断控制器（可能有多个），调用驱动里注册的初始化函数，对其进行初始化。
## 4.15 time_init()
初始化Clock和Timer。
## 4.16 console_init()
console初始化。自此以后就可以使用printk()了。非重点，不关心。PS：其实在此前是有printk的，但其打印的内容必须在console_init之后才能打印出来，也就是说之前prinkt的数据都保存在了一个缓冲区内，等到console_init以后才打印出来。
## 4.17 arch_call_rest_init()
这是非常重要的一个函数，它完成了内核引导后期全部的剩余工作，包括设备驱动的加载、init进程的创建等。我们会对它进行仔细分析。
arch_call_rest_init()其实是```rest_init()```的简单封装。rest_init()的主干如下：
```C
noinline void __ref rest_init(void)
{
	struct task_struct *tsk;
	int pid;
	...
	/*
	 * We need to spawn init first so that it obtains pid 1, however
	 * the init task will end up wanting to create kthreads, which, if
	 * we schedule it before we create kthreadd, will OOPS.
	 */
	pid = kernel_thread(kernel_init, NULL, CLONE_FS);  /* ***很重要*** 创建第一个内核线程kernel_init()，PID=1，但还不能够去调度它 */
	...
	pid = kernel_thread(kthreadd, NULL, CLONE_FS | CLONE_FILES);  /* ***很重要*** 创建第二个内核线程kthreadd()，PID=2，负责启动其它内核线程 */
	...
	system_state = SYSTEM_SCHEDULING;
	complete(&kthreadd_done);	/* 释放完成量，给 kernel_init() --> kernel_init_freeable()，于是kernel_init()线程就能够继续执行了 */
	/*
	 * The boot idle thread must execute schedule()
	 * at least once to get things moving:
	 */
	schedule_preempt_disabled();  /* 在关抢占的情况下，启动调度（那么抢占是在什么时候再次被开启的呢？） */
	/* Call into cpu_idle with preempt disabled */
	cpu_startup_entry(CPUHP_ONLINE);  /* 0号进程在完成上述工作之后，就退化成为IDLE循环，在内核态中空转。 */
}
```
可以看到，rest_init()的最重要工作就是创建了两个内核线程：```kernel_init```和```kthreadd```。其中kernel_init()完成驱动的初始化等工作后，会去执行init进程，从而演变为用户空间的1号进程；kthreadd则作为2号线程，始终运行在内核态，用于启动其他刚创建出来的内核线程；而rest_init()自身作为0号线程，会在执行完上述操作之后，通过调用cpu_startup_entry()退化成IDLE循环，在内核态中空转。
接下来我们分析两个重点函数：kernel_init()和kthreadd()。
### 4.17.1 kernel_init()
```C
static int __ref kernel_init(void *unused)
{
	int ret;

	kernel_init_freeable();  /* ***重要*** 多核启动、设备驱动的初始化，都在这里执行 */
	...
	if (ramdisk_execute_command) {  /* 如果ramdisk里的init进程有效，则运行之 */
		ret = run_init_process(ramdisk_execute_command);
		...
	}
	if (execute_command) {  /* 如果启动命令行里指定了init进程，则运行之 */
		ret = run_init_process(execute_command);
		if (!ret)
			return 0;  /* 成功 */
		panic("Requested init %s failed (error %d).",
		      execute_command, ret);
	}
	if (!try_to_run_init_process("/sbin/init") ||  /* 依次尝试运行如下进程 */
	    !try_to_run_init_process("/etc/init") ||
	    !try_to_run_init_process("/bin/init") ||
	    !try_to_run_init_process("/bin/sh"))
		return 0;  /* 成功 */
	/* 没找到init进程。挂了... */
	panic("No working init found.  Try passing init= option to kernel. "
	      "See Linux Documentation/admin-guide/init.rst for guidance.");
}
```
上述执行流程还是比较清晰的。
这里重点讲解下```kernel_init_freeable()```->```do_basic_setup()```： 
```C
/*
 * Ok, the machine is now initialized. None of the devices
 * have been touched yet, but the CPU subsystem is up and
 * running, and memory and process management works.
 *
 * Now we can finally start doing some real work..
 */
static void __init do_basic_setup(void)
{
	cpuset_init_smp();
	driver_init();		/* ***重要*** 设备驱动初始化 */
	init_irq_proc();  	/* procfs-irq（/proc/irq/）相关的初始化。 */
	do_ctors();
	usermodehelper_enable();
	do_initcalls();		/* 执行所有的initcall函数 */
}
```
在driver_init()里，分别对devtmpfs、sysfs、platform总线等做了初始化，而驱动程序里的probe()函数，也是在这个阶段得到了执行。
而do_initcalls()则按照各个内核模块初始化函数的启动级别（1~7），按顺序调用初始化函数。
回到kernel_init()，来分析一下它执行init进程的逻辑：首先检查ramdisk（可能是initrd或者initramfs？），如果存在则执行其中的/init程序；否则尝试启动内核命令行所指定的init程序；如果前两步都没有执行，则依次尝试启动"/sbin/init"、"/etc/init"、"/bin/init"、"/bin/sh"；如果上述尝试均告失败，则内核panic。
### 4.17.2 kthreadd()
kthreadd是内核线程的守护线程，用于启动其他的内核线程。其逻辑比较简单，我们贴上代码，不再展开讲解：
```C
int kthreadd(void *unused)
{
	struct task_struct *tsk = current;
	/* Setup a clean context for our children to inherit. */
	set_task_comm(tsk, "kthreadd");
	ignore_signals(tsk);
	...
	for (;;) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (list_empty(&kthread_create_list))  /* 如果list为空 */ 
			schedule();  /* 则调度出去，本任务进入睡眠状态（TASK_INTERRUPTIBLE） */
		__set_current_state(TASK_RUNNING);
		...
		while (!list_empty(&kthread_create_list)) {  /* 遍历 kthread_create_list */
			struct kthread_create_info *create;
			create = list_entry(kthread_create_list.next,  /* 取出list里的一个元素 */
					    struct kthread_create_info, list);
			list_del_init(&create->list);
			...
			create_kthread(create);  /* 创建这个线程 */
			...
		}
		...
	}
	return 0;
}
```
# 5. 总结回顾
这里引用一位网友的总结，我感觉十分到位：
>内核启动过程包括start_kernel()之前和之后，之前全部是做初始化的汇编指令，之后开始C代码的操作系统初始化，最后执行第一个用户态进程init。
>一般分两阶段启动，先是利用initrd的内存文件系统，然后切换到硬盘文件系统继续启动。initrd文件的功能主要有两个：1、提供开机必需的但kernel文件（即vmlinuz）没有提供的驱动模块(modules)  2、负责加载硬盘上的根文件系统并执行其中的/sbin/init程序进而将开机过程持续下去。
>start_kernel()是汇编代码运行后，对系统环境初始化的开始。0号进程是启动时较早人为建立的，然后0号进程fork产生了第一个用户态进程1号进程，1号进程载入磁盘上的init程序，生成了系统所需的所有进程，然后0号进程就转变为idle进程，在系统中空转。
>idle进程不是只有一个，在SMP多处理器机上，主处理器的idle进程是由最初的0号转变而来，从处理器的idle是由主处理器fork产生，PID皆为0，每个处理器的idle在机器空闲时空转，参与调度功能。
>道生一（start_kernel....cpu_idle），一生二（kernel_init和kthreadd），二生三（即前面0、1和2三个进程），三生万物（1号进程是所有用户态进程的祖先，2号进程是所有内核线程的祖先）。新内核的核心代码已经优化的相当干净，都符合中国传统文化精神了。

漫长的启动过程到这里就结束了。历经无数艰难险阻，终于赢得风平浪静。
文中标有@TODO之处，是我暂时未能吃透的知识点，欢迎读者朋友补充。
# 6. FAQ
## 6.1 内存模块的初始化过程是怎样的？
@TODO
## 6.2 Clock模块的初始化过程是怎样的？
@TODO
## 6.3 Timer模块的初始化过程是怎样的？
@TODO
## 6.4 多核（SMP）的启动过程是怎样的？
@TODO
## 6.5 驱动里使用__setup()注册的命令行参数解析函数，是在哪个阶段被执行的？
@TODO
