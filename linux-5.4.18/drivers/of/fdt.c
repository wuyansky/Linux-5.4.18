// SPDX-License-Identifier: GPL-2.0
/*
 * Functions for working with the Flattened Device Tree data format
 *
 * Copyright 2009 Benjamin Herrenschmidt, IBM Corp
 * benh@kernel.crashing.org
 */

#define pr_fmt(fmt)	"OF: fdt: " fmt

#include <linux/crc32.h>
#include <linux/kernel.h>
#include <linux/initrd.h>
#include <linux/memblock.h>
#include <linux/mutex.h>
#include <linux/of.h>
#include <linux/of_fdt.h>
#include <linux/of_reserved_mem.h>
#include <linux/sizes.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/libfdt.h>
#include <linux/debugfs.h>
#include <linux/serial_core.h>
#include <linux/sysfs.h>
#include <linux/random.h>

#include <asm/setup.h>  /* for COMMAND_LINE_SIZE */
#include <asm/page.h>

#include "of_private.h"

/*
 * of_fdt_limit_memory - limit the number of regions in the /memory node
 * @limit: maximum entries
 *
 * Adjust the flattened device tree to have at most 'limit' number of
 * memory entries in the /memory node. This function may be called
 * any time after initial_boot_param is set.
 */
void __init of_fdt_limit_memory(int limit)
{
	int memory;
	int len;
	const void *val;
	int nr_address_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;
	int nr_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
	const __be32 *addr_prop;
	const __be32 *size_prop;
	int root_offset;
	int cell_size;

	root_offset = fdt_path_offset(initial_boot_params, "/");
	if (root_offset < 0)
		return;

	addr_prop = fdt_getprop(initial_boot_params, root_offset,
				"#address-cells", NULL);
	if (addr_prop)
		nr_address_cells = fdt32_to_cpu(*addr_prop);

	size_prop = fdt_getprop(initial_boot_params, root_offset,
				"#size-cells", NULL);
	if (size_prop)
		nr_size_cells = fdt32_to_cpu(*size_prop);

	cell_size = sizeof(uint32_t)*(nr_address_cells + nr_size_cells);

	memory = fdt_path_offset(initial_boot_params, "/memory");
	if (memory > 0) {
		val = fdt_getprop(initial_boot_params, memory, "reg", &len);
		if (len > limit*cell_size) {
			len = limit*cell_size;
			pr_debug("Limiting number of entries to %d\n", limit);
			fdt_setprop(initial_boot_params, memory, "reg", val,
					len);
		}
	}
}

static bool of_fdt_device_is_available(const void *blob, unsigned long node)
{	/* 检查某个节点是否可用（即启用还是禁用状态） */
	const char *status = fdt_getprop(blob, node, "status", NULL);

	if (!status)  /* 若找不到名为"status"的属性，则认为该节点可用的 */
		return true;

	if (!strcmp(status, "ok") || !strcmp(status, "okay"))  /* 若"status"的值是"ok"或"okay"，亦认为该节点是可用的 */
		return true;

	return false;  /* 其他情况：不可用 */
}

static void *unflatten_dt_alloc(void **mem, unsigned long size,
				       unsigned long align)
{
	void *res;

	*mem = PTR_ALIGN(*mem, align);
	res = *mem;
	*mem += size;

	return res;
}

static void populate_properties(const void *blob,
				int offset,
				void **mem,
				struct device_node *np,
				const char *nodename,
				bool dryrun)
{
	struct property *pp, **pprev = NULL;
	int cur;
	bool has_name = false;

	pprev = &np->properties;
	for (cur = fdt_first_property_offset(blob, offset);
	     cur >= 0;
	     cur = fdt_next_property_offset(blob, cur)) {
		const __be32 *val;
		const char *pname;
		u32 sz;

		val = fdt_getprop_by_offset(blob, cur, &pname, &sz);
		if (!val) {
			pr_warn("Cannot locate property at 0x%x\n", cur);
			continue;
		}

		if (!pname) {
			pr_warn("Cannot find property name at 0x%x\n", cur);
			continue;
		}

		if (!strcmp(pname, "name"))
			has_name = true;

		pp = unflatten_dt_alloc(mem, sizeof(struct property),
					__alignof__(struct property));
		if (dryrun)
			continue;

		/* We accept flattened tree phandles either in
		 * ePAPR-style "phandle" properties, or the
		 * legacy "linux,phandle" properties.  If both
		 * appear and have different values, things
		 * will get weird. Don't do that.
		 */
		if (!strcmp(pname, "phandle") ||
		    !strcmp(pname, "linux,phandle")) {
			if (!np->phandle)
				np->phandle = be32_to_cpup(val);
		}

		/* And we process the "ibm,phandle" property
		 * used in pSeries dynamic device tree
		 * stuff
		 */
		if (!strcmp(pname, "ibm,phandle"))
			np->phandle = be32_to_cpup(val);

		pp->name   = (char *)pname;
		pp->length = sz;
		pp->value  = (__be32 *)val;
		*pprev     = pp;
		pprev      = &pp->next;
	}

	/* With version 0x10 we may not have the name property,
	 * recreate it here from the unit name if absent
	 */
	if (!has_name) {
		const char *p = nodename, *ps = p, *pa = NULL;
		int len;

		while (*p) {
			if ((*p) == '@')
				pa = p;
			else if ((*p) == '/')
				ps = p + 1;
			p++;
		}

		if (pa < ps)
			pa = p;
		len = (pa - ps) + 1;
		pp = unflatten_dt_alloc(mem, sizeof(struct property) + len,
					__alignof__(struct property));
		if (!dryrun) {
			pp->name   = "name";
			pp->length = len;
			pp->value  = pp + 1;
			*pprev     = pp;
			pprev      = &pp->next;
			memcpy(pp->value, ps, len - 1);
			((char *)pp->value)[len - 1] = 0;
			pr_debug("fixed up name for %s -> %s\n",
				 nodename, (char *)pp->value);
		}
	}

	if (!dryrun)
		*pprev = NULL;
}

static bool populate_node(const void *blob,
			  int offset,
			  void **mem,
			  struct device_node *dad,
			  struct device_node **pnp,
			  bool dryrun)
{
	struct device_node *np;
	const char *pathp;
	unsigned int l, allocl;

	pathp = fdt_get_name(blob, offset, &l);
	if (!pathp) {
		*pnp = NULL;
		return false;
	}

	allocl = ++l;

	np = unflatten_dt_alloc(mem, sizeof(struct device_node) + allocl,
				__alignof__(struct device_node));
	if (!dryrun) {
		char *fn;
		of_node_init(np);
		np->full_name = fn = ((char *)np) + sizeof(*np);

		memcpy(fn, pathp, l);

		if (dad != NULL) {
			np->parent = dad;
			np->sibling = dad->child;
			dad->child = np;
		}
	}

	populate_properties(blob, offset, mem, np, pathp, dryrun);
	if (!dryrun) {
		np->name = of_get_property(np, "name", NULL);
		if (!np->name)
			np->name = "<NULL>";
	}

	*pnp = np;
	return true;
}

static void reverse_nodes(struct device_node *parent)
{
	struct device_node *child, *next;

	/* In-depth first */
	child = parent->child;
	while (child) {
		reverse_nodes(child);

		child = child->sibling;
	}

	/* Reverse the nodes in the child list */
	child = parent->child;
	parent->child = NULL;
	while (child) {
		next = child->sibling;

		child->sibling = parent->child;
		parent->child = child;
		child = next;
	}
}

/**
 * unflatten_dt_nodes - Alloc and populate a device_node from the flat tree
 * @blob: The parent device tree blob
 * @mem: Memory chunk to use for allocating device nodes and properties
 * @dad: Parent struct device_node
 * @nodepp: The device_node tree created by the call
 *
 * It returns the size of unflattened device tree or error code
 */
static int unflatten_dt_nodes(const void *blob,
			      void *mem,
			      struct device_node *dad,
			      struct device_node **nodepp)
{
	struct device_node *root;
	int offset = 0, depth = 0, initial_depth = 0;
#define FDT_MAX_DEPTH	64
	struct device_node *nps[FDT_MAX_DEPTH];
	void *base = mem;
	bool dryrun = !base;

	if (nodepp)
		*nodepp = NULL;

	/*
	 * We're unflattening device sub-tree if @dad is valid. There are
	 * possibly multiple nodes in the first level of depth. We need
	 * set @depth to 1 to make fdt_next_node() happy as it bails
	 * immediately when negative @depth is found. Otherwise, the device
	 * nodes except the first one won't be unflattened successfully.
	 */
	if (dad)
		depth = initial_depth = 1;

	root = dad;
	nps[depth] = dad;

	for (offset = 0;
	     offset >= 0 && depth >= initial_depth;
	     offset = fdt_next_node(blob, offset, &depth)) {
		if (WARN_ON_ONCE(depth >= FDT_MAX_DEPTH))
			continue;

		if (!IS_ENABLED(CONFIG_OF_KOBJ) &&
		    !of_fdt_device_is_available(blob, offset))
			continue;

		if (!populate_node(blob, offset, &mem, nps[depth],
				   &nps[depth+1], dryrun))
			return mem - base;

		if (!dryrun && nodepp && !*nodepp)
			*nodepp = nps[depth+1];
		if (!dryrun && !root)
			root = nps[depth+1];
	}

	if (offset < 0 && offset != -FDT_ERR_NOTFOUND) {
		pr_err("Error %d processing FDT\n", offset);
		return -EINVAL;
	}

	/*
	 * Reverse the child list. Some drivers assumes node order matches .dts
	 * node order
	 */
	if (!dryrun)
		reverse_nodes(root);

	return mem - base;
}

/**
 * __unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens a device-tree, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 * @blob: The blob to expand
 * @dad: Parent device node
 * @mynodes: The device_node tree created by the call
 * @dt_alloc: An allocator that provides a virtual address to memory
 * for the resulting tree
 * @detached: if true set OF_DETACHED on @mynodes
 *
 * Returns NULL on failure or the memory chunk containing the unflattened
 * device tree on success.
 */
void *__unflatten_device_tree(const void *blob,
			      struct device_node *dad,
			      struct device_node **mynodes,
			      void *(*dt_alloc)(u64 size, u64 align),
			      bool detached)
{
	int size;
	void *mem;

	pr_debug(" -> unflatten_device_tree()\n");

	if (!blob) {
		pr_debug("No device tree pointer\n");
		return NULL;
	}

	pr_debug("Unflattening device tree:\n");
	pr_debug("magic: %08x\n", fdt_magic(blob));
	pr_debug("size: %08x\n", fdt_totalsize(blob));
	pr_debug("version: %08x\n", fdt_version(blob));

	if (fdt_check_header(blob)) {
		pr_err("Invalid device tree blob header\n");
		return NULL;
	}

	/* First pass, scan for size */
	size = unflatten_dt_nodes(blob, NULL, dad, NULL);
	if (size < 0)
		return NULL;

	size = ALIGN(size, 4);
	pr_debug("  size is %d, allocating...\n", size);

	/* Allocate memory for the expanded device tree */
	mem = dt_alloc(size + 4, __alignof__(struct device_node));
	if (!mem)
		return NULL;

	memset(mem, 0, size);

	*(__be32 *)(mem + size) = cpu_to_be32(0xdeadbeef);

	pr_debug("  unflattening %p...\n", mem);

	/* Second pass, do actual unflattening */
	unflatten_dt_nodes(blob, mem, dad, mynodes);
	if (be32_to_cpup(mem + size) != 0xdeadbeef)
		pr_warning("End of tree marker overwritten: %08x\n",
			   be32_to_cpup(mem + size));

	if (detached && mynodes) {
		of_node_set_flag(*mynodes, OF_DETACHED);
		pr_debug("unflattened tree is detached\n");
	}

	pr_debug(" <- unflatten_device_tree()\n");
	return mem;
}

static void *kernel_tree_alloc(u64 size, u64 align)
{
	return kzalloc(size, GFP_KERNEL);
}

static DEFINE_MUTEX(of_fdt_unflatten_mutex);

/**
 * of_fdt_unflatten_tree - create tree of device_nodes from flat blob
 * @blob: Flat device tree blob
 * @dad: Parent device node
 * @mynodes: The device tree created by the call
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 *
 * Returns NULL on failure or the memory chunk containing the unflattened
 * device tree on success.
 */
void *of_fdt_unflatten_tree(const unsigned long *blob,
			    struct device_node *dad,
			    struct device_node **mynodes)
{
	void *mem;

	mutex_lock(&of_fdt_unflatten_mutex);
	mem = __unflatten_device_tree(blob, dad, mynodes, &kernel_tree_alloc,
				      true);
	mutex_unlock(&of_fdt_unflatten_mutex);

	return mem;
}
EXPORT_SYMBOL_GPL(of_fdt_unflatten_tree);

/* Everything below here references initial_boot_params directly. */
int __initdata dt_root_addr_cells;  /* 由设备树解析而来的、顶层的"#addr-cells"的值 */
int __initdata dt_root_size_cells;  /* 由设备树解析而来的、顶层的"#size-cells"的值 */

void *initial_boot_params __ro_after_init;

#ifdef CONFIG_OF_EARLY_FLATTREE

static u32 of_fdt_crc32;

/**
 * res_mem_reserve_reg() - reserve all memory described in 'reg' property
 */
static int __init __reserved_mem_reserve_reg(unsigned long node,
					     const char *uname)
{	/* 功能：解析设备树里的一个偏移为node、名为uname的"保留内存"节点，将这个节点下的内存（可能有多段）添加到系统的保留内存里。返回：0：成功；负数：失败 */
	int t_len = (dt_root_addr_cells + dt_root_size_cells) * sizeof(__be32);  /* reg节点的值是一个list，这里的t_len是list里的单个值所占的字节数 */
	phys_addr_t base, size;
	int len;
	const __be32 *prop;
	int first = 1;
	bool nomap;

	prop = of_get_flat_dt_prop(node, "reg", &len);  /* 解析"reg"节点，得到其值prop和长度len */
	if (!prop)
		return -ENOENT;

	if (len && len % t_len != 0) {
		pr_err("Reserved memory: invalid reg property in '%s', skipping node.\n",
		       uname);
		return -EINVAL;
	}

	nomap = of_get_flat_dt_prop(node, "no-map", NULL) != NULL;  /* 解析"no-map"节点，得到其值nomap */

	while (len >= t_len) {  /* 遍历"reg"节点的值 */
		base = dt_mem_next_cell(dt_root_addr_cells, &prop);  /* 迭代取出每一段内存的起始地址base */
		size = dt_mem_next_cell(dt_root_size_cells, &prop);  /* 迭代取出每一段内存的长度size */

		if (size &&
		    early_init_dt_reserve_memory_arch(base, size, nomap) == 0)  /* 将这段内存添加到系统里，作为保留内存使用 */
			pr_debug("Reserved memory: reserved region for node '%s': base %pa, size %ld MiB\n",  /* 成功 */
				uname, &base, (unsigned long)size / SZ_1M);
		else  /* 失败 */
			pr_info("Reserved memory: failed to reserve memory for node '%s': base %pa, size %ld MiB\n",
				uname, &base, (unsigned long)size / SZ_1M);

		len -= t_len;
		if (first) {  /* 一个节点下可以通过"reg"指定多段内存，这里仅登记第一段内存 */
			fdt_reserved_mem_save_node(node, uname, base, size);
			first = 0;
		}
	}
	return 0;
}

/**
 * __reserved_mem_check_root() - check if #size-cells, #address-cells provided
 * in /reserved-memory matches the values supported by the current implementation,
 * also check if ranges property has been provided
 */
static int __init __reserved_mem_check_root(unsigned long node)
{
	const __be32 *prop;

	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_size_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	if (!prop || be32_to_cpup(prop) != dt_root_addr_cells)
		return -EINVAL;

	prop = of_get_flat_dt_prop(node, "ranges", NULL);
	if (!prop)
		return -EINVAL;
	return 0;
}

/**
 * fdt_scan_reserved_mem() - scan a single FDT node for reserved memory
 */
static int __init __fdt_scan_reserved_mem(unsigned long node, const char *uname,
					  int depth, void *data)
{	/* 功能：这是被of_scan_flat_dt()所调用的回调函数。它寻找设备树里的"reserved-memory"节点，将对应的保留内存添加到系统里。返回：true或false */
	static int found;
	int err;
	/* 注意：由于of_scan_flat_dt()里对设备树的遍历方式为前序深度遍历，这意味着传进来的参数depth不是递增的，而是类似于"1,2,3,3,1,2,1,2,3,4"这样的 */
	if (!found && depth == 1 && strcmp(uname, "reserved-memory") == 0) {  /* (stage 2) 在顶层找到了"reserved-memory"节点 */
		if (__reserved_mem_check_root(node) != 0) {  /* 异常处理 */
			pr_err("Reserved memory: unsupported node format, ignoring\n");
			/* break scan */
			return 1;
		}
		found = 1;  /* 我们仅仅做个标记，就返回。下一次调用本函数，就会跳到最后一个分支里（else if (found && depth >= 2)），对"reserved-memory"的子节点进行遍历 */
		/* scan next node */
		return 0;
	} else if (!found) {  /* (stage 1) 没找到。刚开始遍历时，会从这个分支开始 */
		/* scan next node */
		return 0;  /* 继续找，直到进前面的分支 */
	} else if (found && depth < 2) {  /* (stage 4) 已经遍历完"reserved-memory"节点，回到其兄弟节点了 */
		/* scanning of /reserved-memory has been finished */
		return 1;  /* 结束遍历 */
	} /* else if (found && depth >= 2) { ... */  /* (stage 3) 当前节点是"reserved-memory"的子节点 */

	if (!of_fdt_device_is_available(initial_boot_params, node))  /* 检查节点是否被禁用了 */
		return 0;

	err = __reserved_mem_reserve_reg(node, uname);  /* 将当前节点下的所有保留内存都添加到系统里 */
	if (err == -ENOENT && of_get_flat_dt_prop(node, "size", NULL))  /* 如果该节点没有reg属性，但有size属性 */
		fdt_reserved_mem_save_node(node, uname, 0, 0);  /* 则登记一个起始地址为0、长度为0的保留内存到系统里（不知道为啥） */

	/* scan next node */
	return 0;
}

/**
 * early_init_fdt_scan_reserved_mem() - create reserved memory regions
 *
 * This function grabs memory from early allocator for device exclusive use
 * defined in device tree structures. It should be called by arch specific code
 * once the early allocator (i.e. memblock) has been fully activated.
 */
void __init early_init_fdt_scan_reserved_mem(void)
{	/* 从设备树里获取"/memreserve/"和"reserved-memory"所声明的保留内存，将其注册到系统里，并对其进行初始化 */
	int n;
	u64 base, size;

	if (!initial_boot_params)	/* 检查DTB是否已就绪 */
		return;

	/* Process header /memreserve/ fields */
	for (n = 0; ; n++) {  /* 遍历DTB里的"/memreserve/"节点（注：此类节点不能配置nomap属性，因此默认都是要被map的） */
		fdt_get_mem_rsv(initial_boot_params, n, &base, &size);  /* 从DTB里解析出第n段保留内存的起始地址base和长度size */
		if (!size)
			break;
		early_init_dt_reserve_memory_arch(base, size, false);  /* 将这段保留内存添加到系统里，并为其建立页表映射 */
	}

	of_scan_flat_dt(__fdt_scan_reserved_mem, NULL);  /* 遍历设备树的每个节点，对每个节点调用__fdt_scan_reserved_mem()。即寻找设备树里的"reserved-memory"节点，将对应的保留内存添加到系统里。 */
	fdt_init_reserved_mem();  /* 初始化"reserved-memory"对应的内存 */
}

/**
 * early_init_fdt_reserve_self() - reserve the memory used by the FDT blob
 */
void __init early_init_fdt_reserve_self(void)
{
	if (!initial_boot_params)
		return;

	/* Reserve the dtb region */
	early_init_dt_reserve_memory_arch(__pa(initial_boot_params),
					  fdt_totalsize(initial_boot_params),
					  false);
}

/**
 * of_scan_flat_dt - scan flattened tree blob and call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan the flattened device-tree, it is
 * used to extract the memory information at boot before we can
 * unflatten the tree
 */
int __init of_scan_flat_dt(int (*it)(unsigned long node,  /* it: 回调函数。在搜索设备树时，对每一个节点调用一次 */
				     const char *uname, int depth,
				     void *data),
			   void *data)  /* data: 传递给回调函数的最后一个参数 */
{   /* 功能：遍历设备树，针对每个节点，调用回调函数it，并将参数data传递给该回调函数，直到回调函数返回成功为止。返回：true或false */
	const void *blob = initial_boot_params;  /* blob是二进制的设备树在内存中的首地址（虚拟），可供解析 */
	const char *pathp;
	int offset, rc = 0, depth = -1;

	if (!blob)
		return 0;
	/* 若将设备树看成二叉树，则这里的遍历方式为前序深度遍历，即按照“根-左-右”的顺序递归遍历。也就是说，先深度遍历当前节点的所有子节点，然后再跳到当前节点的兄弟节点，进行遍历 */
	for (offset = fdt_next_node(blob, -1, &depth);  /* 从根节点开始遍历每个节点，得到每个节点的偏移和深度 */
	     offset >= 0 && depth >= 0 && !rc;  /* 注意这里的停止条件：rc!=0，也就是说一旦回调函数执行成功，循环就停止了 */
	     offset = fdt_next_node(blob, offset, &depth)) {

		pathp = fdt_get_name(blob, offset, NULL);  /* 根据偏移，获取当前节点的名字pathp */
		if (*pathp == '/')  /* 绝对路径？ */
			pathp = kbasename(pathp);  /* 去掉路径，只留下最后一部分节点名 */
		rc = it(offset, pathp, depth, data);  /* 针对当前节点，调用回调函数 */
	}
	return rc;
}

/**
 * of_scan_flat_dt_subnodes - scan sub-nodes of a node call callback on each.
 * @it: callback function
 * @data: context data pointer
 *
 * This function is used to scan sub-nodes of a node.
 */
int __init of_scan_flat_dt_subnodes(unsigned long parent,
				    int (*it)(unsigned long node,
					      const char *uname,
					      void *data),
				    void *data)
{
	const void *blob = initial_boot_params;
	int node;

	fdt_for_each_subnode(node, blob, parent) {
		const char *pathp;
		int rc;

		pathp = fdt_get_name(blob, node, NULL);
		if (*pathp == '/')
			pathp = kbasename(pathp);
		rc = it(node, pathp, data);
		if (rc)
			return rc;
	}
	return 0;
}

/**
 * of_get_flat_dt_subnode_by_name - get the subnode by given name
 *
 * @node: the parent node
 * @uname: the name of subnode
 * @return offset of the subnode, or -FDT_ERR_NOTFOUND if there is none
 */

int __init of_get_flat_dt_subnode_by_name(unsigned long node, const char *uname)
{
	return fdt_subnode_offset(initial_boot_params, node, uname);
}

/**
 * of_get_flat_dt_root - find the root node in the flat blob
 */
unsigned long __init of_get_flat_dt_root(void)
{
	return 0;
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob, return the property ptr
 *
 * This function can be used within scan_flattened_dt callback to get
 * access to properties
 */
const void *__init of_get_flat_dt_prop(unsigned long node, const char *name,  /* node是节点相对二进制设备树的起始位置的偏移量（从这里开始查找），name是要查找的属性名 */
				       int *size)  /* size是（传出的）找到的属性的值的长度 */
{	/* 从设备树里偏移为node处开始查找名为name的节点，返回节点的值的指针，得到值的长度size */
	return fdt_getprop(initial_boot_params, node, name, size);
}

/**
 * of_fdt_is_compatible - Return true if given node from the given blob has
 * compat in its compatible list
 * @blob: A device tree blob
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 *
 * On match, returns a non-zero value with smaller values returned for more
 * specific compatible values.
 */
static int of_fdt_is_compatible(const void *blob,  /* blob：二进制的设备树的（虚拟）起始地址 */
		      unsigned long node, const char *compat)  /* node：开始查找的偏移量；compat：待匹配的"compatible"属性 */
{	/* 功能：在设备数blob里，从偏移为node处找到"compatible"节点，将其值（可能有多个）分别与compat进行比较。返回：0：匹配失败；其他正整数：匹配成功（数值越小，说明匹配度越高） */
	const char *cp;
	int cplen;
	unsigned long l, score = 0;

	cp = fdt_getprop(blob, node, "compatible", &cplen);  /* 获取"compatible"属性的值cp以及长度cplen */
	if (cp == NULL)  /* 得到的cp类似于 "allwinner,sun8i1\0allwinner,sun8i2\0" ，即多个字符串连在一起，中间以'\0'分隔 */
		return 0;
	while (cplen > 0) {
		score++;  /* 随着比较次数的增多，score逐次增大（score越小，说明匹配度越高） */
		if (of_compat_cmp(cp, compat, strlen(compat)) == 0)  /* 不区分大小写，比较cp和compat */
			return score;  /* 如果两者完全相等，则返回 */
		l = strlen(cp) + 1;  /* 得出当前"compatible"值的长度。这里的'+1'其实是为了跳过字符串末尾的'\0' */
		cp += l;  /* 跳过当前的"compatible"值，进入下一轮比较 */
		cplen -= l;
	}

	return 0;
}

/**
 * of_flat_dt_is_compatible - Return true if given node has compat in compatible list
 * @node: node to test
 * @compat: compatible string to compare with compatible list.
 */
int __init of_flat_dt_is_compatible(unsigned long node, const char *compat)
{
	return of_fdt_is_compatible(initial_boot_params, node, compat);
}

/**
 * of_flat_dt_match - Return true if node matches a list of compatible values
 */
static int __init of_flat_dt_match(unsigned long node, const char *const *compat)  /* node: 节点偏移； char *compat[]: 用于匹配的字符串数组，以NULL结尾 */
{	/* 功能：从设备树偏移为node处开始，针对compat[]的每个元素，逐个匹配。返回：匹配失败返回0，匹配成功返回正整数，数值越小说明匹配度越高 */
	unsigned int tmp, score = 0;

	if (!compat)
		return 0;

	while (*compat) {  /* 遍历compat[] */
		tmp = of_fdt_is_compatible(initial_boot_params, node, *compat);  /* 将compat[i]与设备树里的"compatible"字段进行匹配 */
		if (tmp && (score == 0 || (tmp < score)))  /* 如果匹配度更高 */
			score = tmp;  /* 则更新score */
		compat++;
	}

	return score;  /* 返回匹配度最高的score */
}

/**
 * of_get_flat_dt_prop - Given a node in the flat blob, return the phandle
 */
uint32_t __init of_get_flat_dt_phandle(unsigned long node)
{
	return fdt_get_phandle(initial_boot_params, node);
}

struct fdt_scan_status {
	const char *name;
	int namelen;
	int depth;
	int found;
	int (*iterator)(unsigned long node, const char *uname, int depth, void *data);
	void *data;
};

const char * __init of_flat_dt_get_machine_name(void)
{   /* 从设备树的根节点下查找节点"model"或"compatible"，返回其值 */
	const char *name;
	unsigned long dt_root = of_get_flat_dt_root();

	name = of_get_flat_dt_prop(dt_root, "model", NULL);
	if (!name)
		name = of_get_flat_dt_prop(dt_root, "compatible", NULL);
	return name;
}

/**
 * of_flat_dt_match_machine - Iterate match tables to find matching machine.
 *
 * @default_match: A machine specific ptr to return in case of no match.
 * @get_next_compat: callback function to return next compatible match table.
 *
 * Iterate through machine match tables to find the best match for the machine
 * compatible string in the FDT.
 */
const void * __init of_flat_dt_match_machine(const void *default_match,
		const void * (*get_next_compat)(const char * const**))
{	/* 功能：将C代码注册的struct machine_desc[]的每个元素的".dt_compat"属性和设备树里的"compatible"属性进行交叉匹配，以得到最佳匹配。返回：匹配成功则返回最佳匹配的machine_desc结构体的指针，匹配失败则返回default_match */
	const void *data = NULL;
	const void *best_data = default_match;
	const char *const *compat;
	unsigned long dt_root;
	unsigned int best_score = ~1, score = 0;

	dt_root = of_get_flat_dt_root();  /* 找到根节点 */
	while ((data = get_next_compat(&compat))) {		/* 遍历（由C代码）已注册的machine_desc列表。针对每个元素，取出其compat值，并返回其machine_desc结构体 */
		score = of_flat_dt_match(dt_root, compat);	/* 针对上面得到的compat，在设备树里（从根节点开始）匹配"compatible"属性 */
		if (score > 0 && score < best_score) {		/* 如果匹配度更高，则更新best_data和best_score */
			best_data = data;
			best_score = score;
		}
	}	/* 循环完毕后，best_data是匹配度最高的machine_desc结构体的指针 */
	if (!best_data) {  /* 异常：匹配失败 */
		const char *prop;
		int size;

		pr_err("\n unrecognized device tree list:\n[ ");

		prop = of_get_flat_dt_prop(dt_root, "compatible", &size);  /* 打印出对应的"compatible"属性列表 */
		if (prop) {
			while (size > 0) {
				printk("'%s' ", prop);
				size -= strlen(prop) + 1;
				prop += strlen(prop) + 1;
			}
		}
		printk("]\n\n");
		return NULL;
	}

	pr_info("Machine model: %s\n", of_flat_dt_get_machine_name());

	return best_data;  /* 正常逻辑 */
}

#ifdef CONFIG_BLK_DEV_INITRD
static void __early_init_dt_declare_initrd(unsigned long start,
					   unsigned long end)
{
	/* ARM64 would cause a BUG to occur here when CONFIG_DEBUG_VM is
	 * enabled since __va() is called too early. ARM64 does make use
	 * of phys_initrd_start/phys_initrd_size so we can skip this
	 * conversion.
	 */
	if (!IS_ENABLED(CONFIG_ARM64)) {
		initrd_start = (unsigned long)__va(start);
		initrd_end = (unsigned long)__va(end);
		initrd_below_start_ok = 1;
	}
}

/**
 * early_init_dt_check_for_initrd - Decode initrd location from flat tree
 * @node: reference to node containing initrd location ('chosen')
 */
static void __init early_init_dt_check_for_initrd(unsigned long node)
{
	u64 start, end;
	int len;
	const __be32 *prop;

	pr_debug("Looking for initrd properties... ");

	prop = of_get_flat_dt_prop(node, "linux,initrd-start", &len);  /* 在设备树里查找此属性，得到此属性的值（数值，非字符串）的起始地址和长度 */
	if (!prop)  /* 没找到 */
		return;
	start = of_read_number(prop, len/4);  /* 对属性的值进行处理，得到u64型的数值，即initrd的物理起始地址 */

	prop = of_get_flat_dt_prop(node, "linux,initrd-end", &len);
	if (!prop)
		return;
	end = of_read_number(prop, len/4);  /* 同上，得到initrd的物理结束地址 */

	__early_init_dt_declare_initrd(start, end);  /* 通过物理地址得到虚拟地址。仅对ARM64有效 */
	phys_initrd_start = start;  /* 将物理起始地址备份到全局变量 */
	phys_initrd_size = end - start;  /* 将长度备份到全局变量 */

	pr_debug("initrd_start=0x%llx  initrd_end=0x%llx\n",
		 (unsigned long long)start, (unsigned long long)end);
}
#else
static inline void early_init_dt_check_for_initrd(unsigned long node)
{
}
#endif /* CONFIG_BLK_DEV_INITRD */

#ifdef CONFIG_SERIAL_EARLYCON

int __init early_init_dt_scan_chosen_stdout(void)
{
	int offset;
	const char *p, *q, *options = NULL;
	int l;
	const struct earlycon_id **p_match;
	const void *fdt = initial_boot_params;

	offset = fdt_path_offset(fdt, "/chosen");
	if (offset < 0)
		offset = fdt_path_offset(fdt, "/chosen@0");
	if (offset < 0)
		return -ENOENT;

	p = fdt_getprop(fdt, offset, "stdout-path", &l);
	if (!p)
		p = fdt_getprop(fdt, offset, "linux,stdout-path", &l);
	if (!p || !l)
		return -ENOENT;

	q = strchrnul(p, ':');
	if (*q != '\0')
		options = q + 1;
	l = q - p;

	/* Get the node specified by stdout-path */
	offset = fdt_path_offset_namelen(fdt, p, l);
	if (offset < 0) {
		pr_warn("earlycon: stdout-path %.*s not found\n", l, p);
		return 0;
	}

	for (p_match = __earlycon_table; p_match < __earlycon_table_end;
	     p_match++) {
		const struct earlycon_id *match = *p_match;

		if (!match->compatible[0])
			continue;

		if (fdt_node_check_compatible(fdt, offset, match->compatible))
			continue;

		of_setup_earlycon(match, offset, options);
		return 0;
	}
	return -ENODEV;
}
#endif

/**
 * early_init_dt_scan_root - fetch the top level address and size cells
 */
int __init early_init_dt_scan_root(unsigned long node, const char *uname,  /* node是节点偏移量；uname参数未使用 */ 
				   int depth, void *data)  /* depth是当前节点的深度；data参数未使用 */
{   /* 功能：在设备树顶层搜索节点"#size-cells"和"#address-cells"，取出其值，放到全局变量dt_root_size_cells和dt_root_addr_cells里。若没有匹配到对应节点，则使用默认值 */
	const __be32 *prop;

	if (depth != 0)
		return 0;

	dt_root_size_cells = OF_ROOT_NODE_SIZE_CELLS_DEFAULT;
	dt_root_addr_cells = OF_ROOT_NODE_ADDR_CELLS_DEFAULT;

	prop = of_get_flat_dt_prop(node, "#size-cells", NULL);
	if (prop)
		dt_root_size_cells = be32_to_cpup(prop);
	pr_debug("dt_root_size_cells = %x\n", dt_root_size_cells);

	prop = of_get_flat_dt_prop(node, "#address-cells", NULL);
	if (prop)
		dt_root_addr_cells = be32_to_cpup(prop);
	pr_debug("dt_root_addr_cells = %x\n", dt_root_addr_cells);

	/* break now */
	return 1;
}

u64 __init dt_mem_next_cell(int s, const __be32 **cellp)
{
	const __be32 *p = *cellp;

	*cellp = p + s;
	return of_read_number(p, s);
}

/**
 * early_init_dt_scan_memory - Look for and parse memory nodes
 */
int __init early_init_dt_scan_memory(unsigned long node, const char *uname,
				     int depth, void *data)  /* data参数未使用 */
{   /* 功能：从设备树里解析可用的内存信息（不含保留内存），并将各段内存注册到系统里 */
	const char *type = of_get_flat_dt_prop(node, "device_type", NULL);
	const __be32 *reg, *endp;
	int l;
	bool hotpluggable;

	/* We are scanning "memory" nodes only */
	if (type == NULL || strcmp(type, "memory") != 0)  /* 要求"device_type"节点存在，且其值为"memory" */
		return 0;  /* 不满足要求 */

	reg = of_get_flat_dt_prop(node, "linux,usable-memory", &l);  /* 检查节点"linux,usable-memory"是否存在 */
	if (reg == NULL)
		reg = of_get_flat_dt_prop(node, "reg", &l);  /* 检查节点"reg"是否存在 */
	if (reg == NULL)
		return 0;  /* 如果上面两个节点都不存在，则失败；否则，得到对应节点的值的指针reg */

	endp = reg + (l / sizeof(__be32));
	hotpluggable = of_get_flat_dt_prop(node, "hotpluggable", NULL);

	pr_debug("memory scan node %s, reg size %d,\n", uname, l);

	while ((endp - reg) >= (dt_root_addr_cells + dt_root_size_cells)) {  /* 遍历每一段内存 */
		u64 base, size;

		base = dt_mem_next_cell(dt_root_addr_cells, &reg);  /* 得到当前这段内存的（物理）基地址和长度 */
		size = dt_mem_next_cell(dt_root_size_cells, &reg);

		if (size == 0)
			continue;
		pr_debug(" - %llx ,  %llx\n", (unsigned long long)base,
		    (unsigned long long)size);

		early_init_dt_add_memory_arch(base, size);  /* 将这段内存添加到系统可用内存里面去 */

		if (!hotpluggable)
			continue;

		if (early_init_dt_mark_hotplug_memory_arch(base, size))  /* 将这段内存标记为“可热插拔的” */
			pr_warn("failed to mark hotplug range 0x%llx - 0x%llx\n",
				base, base + size);
	}

	return 0;
}

int __init early_init_dt_scan_chosen(unsigned long node, const char *uname,  /* node：即offset； uname：节点名*/
				     int depth, void *data)  /* depth：搜索深度；data：传出参数，指向得到的属性值 */
{   /* 此函数的基本功能：解析chosen节点，并传出最终生效的命令行参数。返回值：true或false */
	int l;
	const char *p;
	const void *rng_seed;

	pr_debug("search \"chosen\", depth: %d, uname: %s\n", depth, uname);

	if (depth != 1 || !data ||  /* 检查节点所在的深度 */
	    (strcmp(uname, "chosen") != 0 && strcmp(uname, "chosen@0") != 0))  /* 检查节点名 */
		return 0;  /* 检查未通过 */

	early_init_dt_check_for_initrd(node);  /* 检查是否有dts里是否有initrd的信息，若有，则将其保存到全局变量里 */

	/* Retrieve command line */
	p = of_get_flat_dt_prop(node, "bootargs", &l);  /* 查找bootargs节点，得到其值（字符串）为p，长度为l */
	if (p != NULL && l > 0)  /* 有效 */
		strlcpy(data, p, min(l, COMMAND_LINE_SIZE));  /* 将值赋给data */

	/*
	 * CONFIG_CMDLINE is meant to be a default in case nothing else
	 * managed to set the command line, unless CONFIG_CMDLINE_FORCE
	 * is set in which case we override whatever was found earlier.
	 */
#ifdef CONFIG_CMDLINE  /* 如果内核里配置了该项（其值就是命令内容） */
#if defined(CONFIG_CMDLINE_EXTEND)
	strlcat(data, " ", COMMAND_LINE_SIZE);
	strlcat(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);  /* 追加到原有的命令行之后 */
#elif defined(CONFIG_CMDLINE_FORCE)
	strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);  /* 强制覆盖原有的命令行 */
#else
	/* No arguments from boot loader, use kernel's  cmdl*/
	if (!((char *)data)[0])  /* 从设备树（及U-Boot）里没有解析到命令行 */
		strlcpy(data, CONFIG_CMDLINE, COMMAND_LINE_SIZE);  /* 使用内核里配置的命令行 */
#endif
#endif /* CONFIG_CMDLINE */

	pr_debug("Command line is: %s\n", (char*)data);

	rng_seed = of_get_flat_dt_prop(node, "rng-seed", &l);  /* 随机数相关，不用管 */
	if (rng_seed && l > 0) {
		add_bootloader_randomness(rng_seed, l);

		/* try to clear seed so it won't be found. */
		fdt_nop_property(initial_boot_params, node, "rng-seed");

		/* update CRC check value */
		of_fdt_crc32 = crc32_be(~0, initial_boot_params,
				fdt_totalsize(initial_boot_params));
	}

	/* break now */
	return 1;  /* 正常返回 */
}

#ifndef MIN_MEMBLOCK_ADDR
#define MIN_MEMBLOCK_ADDR	__pa(PAGE_OFFSET)
#endif
#ifndef MAX_MEMBLOCK_ADDR
#define MAX_MEMBLOCK_ADDR	((phys_addr_t)~0)
#endif

void __init __weak early_init_dt_add_memory_arch(u64 base, u64 size)  /* 注意：这里的base是物理地址！ */
{	/* 将一段内存（起始地址为base，长度为size）添加到系统里，作为普通内存使用 */
	const u64 phys_offset = MIN_MEMBLOCK_ADDR;

	if (size < PAGE_SIZE - (base & ~PAGE_MASK)) {
		pr_warn("Ignoring memory block 0x%llx - 0x%llx\n",
			base, base + size);
		return;
	}

	if (!PAGE_ALIGNED(base)) {
		size -= PAGE_SIZE - (base & ~PAGE_MASK);
		base = PAGE_ALIGN(base);
	}
	size &= PAGE_MASK;

	if (base > MAX_MEMBLOCK_ADDR) {
		pr_warning("Ignoring memory block 0x%llx - 0x%llx\n",
				base, base + size);
		return;
	}

	if (base + size - 1 > MAX_MEMBLOCK_ADDR) {
		pr_warning("Ignoring memory range 0x%llx - 0x%llx\n",
				((u64)MAX_MEMBLOCK_ADDR) + 1, base + size);
		size = MAX_MEMBLOCK_ADDR - base + 1;
	}

	if (base + size < phys_offset) {
		pr_warning("Ignoring memory block 0x%llx - 0x%llx\n",
			   base, base + size);
		return;
	}
	if (base < phys_offset) {
		pr_warning("Ignoring memory range 0x%llx - 0x%llx\n",
			   base, phys_offset);
		size -= phys_offset - base;
		base = phys_offset;
	}
	memblock_add(base, size);  /* 前面的都是一些检查和预处理。这一句才是主逻辑！ */
}

int __init __weak early_init_dt_mark_hotplug_memory_arch(u64 base, u64 size)
{
	return memblock_mark_hotplug(base, size);
}

int __init __weak early_init_dt_reserve_memory_arch(phys_addr_t base,
					phys_addr_t size, bool nomap)  /* nomap表示无需为这段内存建立页表映射 */
{	/* 功能：将一段内存（起始地址为base，长度为size）添加到系统里，作为保留内存使用。可通过nomap参数选择是否为其建立页表映射。返回：0：成功；负数：失败 */
	if (nomap)
		return memblock_remove(base, size);
	return memblock_reserve(base, size);
}

static void * __init early_init_dt_alloc_memory_arch(u64 size, u64 align)
{
	void *ptr = memblock_alloc(size, align);

	if (!ptr)
		panic("%s: Failed to allocate %llu bytes align=0x%llx\n",
		      __func__, size, align);

	return ptr;
}

bool __init early_init_dt_verify(void *params)  /* params是设备树的（虚拟）起始地址 */
{	/* 校验二进制设备树是否有效 */
	if (!params)
		return false;

	/* check device tree validity */
	if (fdt_check_header(params))
		return false;

	/* Setup flat device-tree pointer */
	initial_boot_params = params;  /* 将首地址保存到全局变量里 */
	of_fdt_crc32 = crc32_be(~0, initial_boot_params,
				fdt_totalsize(initial_boot_params));
	return true;
}


void __init early_init_dt_scan_nodes(void)
{   /* 从设备树里获取内核命令行、"#size-cells"和"#address-cells"以及内存信息，并将其保存到全局变量或注册到系统里 */
	int rc = 0;

	/* Retrieve various information from the /chosen node */
	rc = of_scan_flat_dt(early_init_dt_scan_chosen, boot_command_line);  /* 搜索设备树，得出最终生效的命令行参数，填充到boot_command_line[]里 */
	if (!rc)
		pr_warn("No chosen node found, continuing without\n");

	/* Initialize {size,address}-cells info */
	of_scan_flat_dt(early_init_dt_scan_root, NULL);  /* 获取设备树顶层的"#size-cells"和"#address-cells"的值，放到全局变量dt_root_size_cells和dt_root_addr_cells里。若没有匹配到对应节点，则使用默认值 */

	/* Setup memory, calling early_init_dt_add_memory_arch */
	of_scan_flat_dt(early_init_dt_scan_memory, NULL);  /* 从设备树里解析可用的内存信息，并将各段内存注册到系统里 */
}

bool __init early_init_dt_scan(void *params)
{
	bool status;

	status = early_init_dt_verify(params);
	if (!status)
		return false;

	early_init_dt_scan_nodes();
	return true;
}

/**
 * unflatten_device_tree - create tree of device_nodes from flat blob
 *
 * unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used.
 */
void __init unflatten_device_tree(void)
{
	__unflatten_device_tree(initial_boot_params, NULL, &of_root,  /* 将DTB展开为struct device_node型的数据结构，赋给全局变量of_root */
				early_init_dt_alloc_memory_arch, false);

	/* Get pointer to "/chosen" and "/aliases" nodes for use everywhere */
	of_alias_scan(early_init_dt_alloc_memory_arch);  /* 处理alias */

	unittest_unflatten_overlay_base();
}

/**
 * unflatten_and_copy_device_tree - copy and create tree of device_nodes from flat blob
 *
 * Copies and unflattens the device-tree passed by the firmware, creating the
 * tree of struct device_node. It also fills the "name" and "type"
 * pointers of the nodes so the normal device-tree walking functions
 * can be used. This should only be used when the FDT memory has not been
 * reserved such is the case when the FDT is built-in to the kernel init
 * section. If the FDT memory is reserved already then unflatten_device_tree
 * should be used instead.
 */
void __init unflatten_and_copy_device_tree(void)
{
	int size;
	void *dt;

	if (!initial_boot_params) {
		pr_warn("No valid device tree found, continuing without\n");
		return;
	}

	size = fdt_totalsize(initial_boot_params);
	dt = early_init_dt_alloc_memory_arch(size,
					     roundup_pow_of_two(FDT_V17_SIZE));

	if (dt) {
		memcpy(dt, initial_boot_params, size);
		initial_boot_params = dt;
	}
	unflatten_device_tree();
}

#ifdef CONFIG_SYSFS
static ssize_t of_fdt_raw_read(struct file *filp, struct kobject *kobj,
			       struct bin_attribute *bin_attr,
			       char *buf, loff_t off, size_t count)
{
	memcpy(buf, initial_boot_params + off, count);
	return count;
}

static int __init of_fdt_raw_init(void)
{
	static struct bin_attribute of_fdt_raw_attr =
		__BIN_ATTR(fdt, S_IRUSR, of_fdt_raw_read, NULL, 0);

	if (!initial_boot_params)
		return 0;

	if (of_fdt_crc32 != crc32_be(~0, initial_boot_params,
				     fdt_totalsize(initial_boot_params))) {
		pr_warn("not creating '/sys/firmware/fdt': CRC check failed\n");
		return 0;
	}
	of_fdt_raw_attr.size = fdt_totalsize(initial_boot_params);
	return sysfs_create_bin_file(firmware_kobj, &of_fdt_raw_attr);
}
late_initcall(of_fdt_raw_init);
#endif

#endif /* CONFIG_OF_EARLY_FLATTREE */
