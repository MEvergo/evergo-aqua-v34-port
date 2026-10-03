/* SPDX-License-Identifier: GPL-2.0-or-later */
#include <linux/errno.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/moduleloader.h>
#include <linux/mutex.h>
#include <linux/numa.h>
#include <linux/sched.h>
#include <linux/set_memory.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/vmalloc.h>
#include <linux/wait.h>
#include <asm/cacheflush.h>
#include <asm/memory.h>
#include <asm/pgtable.h>

#include "arch/arm64/reloc.h"
#include "kpm_internal.h"

#define KPM_REGION_TEXT 0
#define KPM_REGION_RO 1
#define KPM_REGION_DATA 2
#define KPM_REGION_COUNT 3
#define KPM_NO_OFFSET KPM_ELF_NO_OFFSET
#define KPM_VERSION_TEXT "1 (native-in-vmlinux)"


struct kpm_image_layout {
	size_t text_size;
	size_t ro_offset;
	size_t ro_size;
	size_t data_offset;
	size_t data_size;
	size_t image_size;
	size_t plt_offset;
	size_t plt_count;
};

static LIST_HEAD(kpm_modules);
static DEFINE_MUTEX(kpm_modules_lock);
static DEFINE_MUTEX(kpm_callback_lock);
static struct task_struct *kpm_callback_task;
static struct kpm_module *kpm_callback_module;

static int kpm_align_size(size_t value, size_t alignment, size_t *aligned)
{
	if (!alignment)
		alignment = 1;
	if (alignment & (alignment - 1))
		return -ENOEXEC;
	if (value > (size_t)-1 - (alignment - 1))
		return -E2BIG;
	*aligned = (value + alignment - 1) & ~(alignment - 1);
	return 0;
}

static int kpm_add_size(size_t left, size_t right, size_t *sum)
{
	if (left > (size_t)-1 - right)
		return -E2BIG;
	*sum = left + right;
	return 0;
}
static int kpm_is_callback_section(const struct kpm_elf_view *view,
				  unsigned int index)
{
	return index == view->section_info || index == view->section_init ||
	       index == view->section_exit || index == view->section_ctl0 ||
	       index == view->section_ctl1 || index == view->section_event;
}


static unsigned int kpm_section_region(const struct kpm_elf_view *view,
				       unsigned int index)
{
	const Elf64_Shdr *section = &view->sections[index];

	if (kpm_is_callback_section(view, index))
		return KPM_REGION_RO;
	if (section->sh_flags & SHF_EXECINSTR)
		return KPM_REGION_TEXT;
	if (section->sh_flags & SHF_WRITE)
		return KPM_REGION_DATA;
	return KPM_REGION_RO;
}

static int kpm_count_branch_relocations(const struct kpm_elf_view *view,
					size_t *count)
{
	unsigned int index;
	size_t branches = 0;

	for (index = 1; index < view->ehdr->e_shnum; index++) {
		const Elf64_Shdr *rela = &view->sections[index];
		const Elf64_Shdr *target;
		const Elf64_Rela *entries;
		size_t entry_count;
		size_t i;

		if (rela->sh_type != SHT_RELA)
			continue;
		target = &view->sections[rela->sh_info];
		if (!(target->sh_flags & SHF_ALLOC))
			continue;
		entries = (const Elf64_Rela *)(view->image + rela->sh_offset);
		entry_count = rela->sh_size / sizeof(*entries);
		for (i = 0; i < entry_count; i++) {
			unsigned int type = ELF64_R_TYPE(entries[i].r_info);

			if (type == R_AARCH64_CALL26 ||
			    type == R_AARCH64_JUMP26) {
				if (branches == (size_t)-1)
					return -E2BIG;
				branches++;
			}
		}
	}
	*count = branches;
	return 0;
}

static int kpm_layout_image(const struct kpm_elf_view *view,
			    size_t *sections,
			    struct kpm_image_layout *layout)
{
	size_t cursor[KPM_REGION_COUNT] = { 0, 0, 0 };
	size_t region_base[KPM_REGION_COUNT];
	size_t text_end;
	size_t plt_bytes;
	size_t i;
	int error;

	memset(layout, 0, sizeof(*layout));
	for (i = 0; i < view->ehdr->e_shnum; i++)
		sections[i] = KPM_NO_OFFSET;

	for (i = 1; i < view->ehdr->e_shnum; i++) {
		const Elf64_Shdr *section = &view->sections[i];
		size_t aligned;
		unsigned int region;

		if (!(section->sh_flags & SHF_ALLOC))
			continue;
		if (section->sh_type != SHT_PROGBITS &&
		    section->sh_type != SHT_NOBITS)
			return -ENOEXEC;
		if (section->sh_flags & KPM_SHF_TLS)
			return -ENOEXEC;
		if ((section->sh_flags & (SHF_WRITE | SHF_EXECINSTR)) ==
		    (SHF_WRITE | SHF_EXECINSTR))
			return -ENOEXEC;
		if (section->sh_addralign > PAGE_SIZE)
			return -ENOEXEC;
		if (section->sh_type == SHT_NOBITS &&
		    (section->sh_flags & SHF_EXECINSTR))
			return -ENOEXEC;

		region = kpm_section_region(view, i);

		error = kpm_align_size(cursor[region], section->sh_addralign,
				       &aligned);
		if (error)
			return error;
		if (section->sh_size > KPM_MAX_IMAGE_SIZE)
			return -E2BIG;
		error = kpm_add_size(aligned, section->sh_size,
				     &cursor[region]);
		if (error)
			return error;
		sections[i] = aligned;
	}

	error = kpm_count_branch_relocations(view, &layout->plt_count);
	if (error)
		return error;
	if (layout->plt_count > (size_t)-1 / (5 * sizeof(u32)))
		return -E2BIG;
	plt_bytes = layout->plt_count * 5 * sizeof(u32);
	error = kpm_align_size(cursor[KPM_REGION_TEXT], 16,
			       &layout->plt_offset);
	if (error)
		return error;
	error = kpm_add_size(layout->plt_offset, plt_bytes, &text_end);
	if (error)
		return error;
	error = kpm_align_size(text_end, PAGE_SIZE, &layout->text_size);
	if (error)
		return error;
	error = kpm_align_size(cursor[KPM_REGION_RO], PAGE_SIZE,
			       &layout->ro_size);
	if (error)
		return error;
	layout->ro_offset = layout->text_size;
	error = kpm_add_size(layout->ro_offset, layout->ro_size,
			     &layout->data_offset);
	if (error)
		return error;
	error = kpm_align_size(cursor[KPM_REGION_DATA], PAGE_SIZE,
			       &layout->data_size);
	if (error)
		return error;
	error = kpm_add_size(layout->data_offset, layout->data_size,
			     &layout->image_size);
	if (error)
		return error;
	if (!layout->text_size)
		return -ENOEXEC;
	if (layout->image_size > KPM_MAX_IMAGE_SIZE)
		return -E2BIG;

	region_base[KPM_REGION_TEXT] = 0;
	region_base[KPM_REGION_RO] = layout->ro_offset;
	region_base[KPM_REGION_DATA] = layout->data_offset;
	for (i = 1; i < view->ehdr->e_shnum; i++) {
		unsigned int region;

		if (sections[i] == KPM_NO_OFFSET)
			continue;
		region = kpm_section_region(view, i);
		if (sections[i] > (size_t)-1 - region_base[region])
			return -E2BIG;
		sections[i] += region_base[region];
	}
	return 0;
}

static int kpm_read_file(const char *path, void **image, size_t *image_size)
{
	struct file *file;
	loff_t position = 0;
	loff_t file_size;
	void *buffer;
	size_t offset = 0;
	int error = 0;

	file = filp_open(path, O_RDONLY, 0);
	if (IS_ERR(file))
		return PTR_ERR(file);
	if (!S_ISREG(file_inode(file)->i_mode)) {
		error = -EINVAL;
		goto out_close;
	}
	file_size = i_size_read(file_inode(file));
	if (file_size <= 0) {
		error = -EINVAL;
		goto out_close;
	}
	if ((u64)file_size > KPM_MAX_ELF_SIZE) {
		error = -EFBIG;
		goto out_close;
	}
	buffer = vmalloc((size_t)file_size);
	if (!buffer) {
		error = -ENOMEM;
		goto out_close;
	}
	while (offset < (size_t)file_size) {
		ssize_t bytes = kernel_read(file, (char *)buffer + offset,
					    (size_t)file_size - offset,
					    &position);

		if (bytes < 0) {
			error = (int)bytes;
			goto out_free;
		}
		if (!bytes) {
			error = -EIO;
			goto out_free;
		}
		offset += (size_t)bytes;
	}
	*image = buffer;
	*image_size = (size_t)file_size;
	goto out_close;

out_free:
	vfree(buffer);
out_close:
	filp_close(file, NULL);
	return error;
}

static void *kpm_alloc_image(size_t size)
{
#ifdef CONFIG_MODULES
	return module_alloc(size);
#else
	return __vmalloc_node_range(size, PAGE_SIZE, MODULES_VADDR, MODULES_END,
				    GFP_KERNEL, PAGE_KERNEL_EXEC, 0,
				    NUMA_NO_NODE,
				    __builtin_return_address(0));
#endif
}

static void kpm_free_image(struct kpm_module *module)
{
	if (!module->image)
		return;
	set_memory_nx((unsigned long)module->image, module->total_pages);
	set_memory_rw((unsigned long)module->image, module->total_pages);
#ifdef CONFIG_MODULES
	module_memfree(module->image);
#else
	vfree(module->image);
#endif
	module->image = NULL;
}

static int kpm_set_image_permissions(struct kpm_module *module)
{
	int data_pages = module->data_size >> PAGE_SHIFT;
	int error;

	error = set_memory_ro((unsigned long)module->image,
			      module->total_pages);
	if (error)
		return error;
	error = set_memory_x((unsigned long)module->image, module->text_pages);
	if (error)
		return error;
	if (data_pages) {
		error = set_memory_rw((unsigned long)module->image +
				      module->data_offset, data_pages);
		if (error)
			return error;
	}
	return 0;
}


static int kpm_parse_metadata(struct kpm_module *module,
			      const struct kpm_elf_view *view)
{
	const Elf64_Shdr *section = &view->sections[view->section_info];
	const char *cursor = (const char *)view->image + section->sh_offset;
	size_t remaining = section->sh_size;
	unsigned int seen = 0;

	while (remaining) {
		const char *end = memchr(cursor, '\0', remaining);
		const char *separator;
		size_t length;
		size_t key_length;
		const char *value;
		size_t value_length;
		char *destination = NULL;
		size_t capacity = 0;
		unsigned int bit = 0;

		if (!end)
			return -ENOEXEC;
		length = end - cursor;
		if (!length) {
			cursor++;
			remaining--;
			continue;
		}
		separator = memchr(cursor, '=', length);
		if (!separator)
			return -ENOEXEC;
		key_length = separator - cursor;
		value = separator + 1;
		value_length = length - key_length - 1;
		if (!key_length || memchr(value, '\n', value_length) ||
		    memchr(value, '\r', value_length))
			return -ENOEXEC;

		if (key_length == sizeof("name") - 1 &&
		    !memcmp(cursor, "name", key_length)) {
			destination = module->name;
			capacity = sizeof(module->name);
			bit = 1U << 0;
		} else if (key_length == sizeof("version") - 1 &&
			   !memcmp(cursor, "version", key_length)) {
			destination = module->version;
			capacity = sizeof(module->version);
			bit = 1U << 1;
		} else if (key_length == sizeof("license") - 1 &&
			   !memcmp(cursor, "license", key_length)) {
			destination = module->license;
			capacity = sizeof(module->license);
			bit = 1U << 2;
		} else if (key_length == sizeof("author") - 1 &&
			   !memcmp(cursor, "author", key_length)) {
			destination = module->author;
			capacity = sizeof(module->author);
			bit = 1U << 3;
		} else if (key_length == sizeof("description") - 1 &&
			   !memcmp(cursor, "description", key_length)) {
			destination = module->description;
			capacity = sizeof(module->description);
			bit = 1U << 4;
		}
		if (destination) {
			if ((seen & bit) || value_length >= capacity)
				return -ENOEXEC;
			memcpy(destination, value, value_length);
			destination[value_length] = '\0';
			seen |= bit;
		}
		remaining -= length + 1;
		cursor = end + 1;
	}

	if (!(seen & (1U << 0)) || !(seen & (1U << 1)) ||
	    !module->name[0] || !module->version[0])
		return -ENOEXEC;
	return 0;
}

static int kpm_relocation_width(unsigned int type)
{
	switch (type) {
	case R_AARCH64_NONE:
		return 0;
	case R_AARCH64_ABS64:
	case R_AARCH64_PREL64:
		return 8;
	case R_AARCH64_ABS16:
	case R_AARCH64_PREL16:
		return 2;
	case R_AARCH64_ABS32:
	case R_AARCH64_PREL32:
		return 4;
	default:
		return 4;
	}
}

static int kpm_symbol_address(const struct kpm_elf_view *view,
			      const size_t *sections,
			      struct kpm_module *module, size_t symbol_index,
			      unsigned long *address)
{
	const Elf64_Sym *symbol;
	unsigned int section_index;
	unsigned int bind;

	if (symbol_index >= view->symbol_count)
		return -ENOEXEC;
	if (!symbol_index) {
		*address = 0;
		return 0;
	}
	symbol = &view->symbols[symbol_index];
	bind = ELF64_ST_BIND(symbol->st_info);
	if (symbol->st_shndx == SHN_UNDEF) {
		const char *name;
		unsigned long resolved;

		if (symbol->st_name >= view->strings_size)
			return -ENOEXEC;
		name = view->strings + symbol->st_name;
		resolved = kpm_compat_resolve(name);
		if (!resolved) {
			if (bind == STB_WEAK) {
				*address = 0;
				return 0;
			}
			return -ENOENT;
		}
		*address = resolved;
		return 0;
	}
	if (symbol->st_shndx == SHN_ABS) {
		*address = symbol->st_value;
		return 0;
	}
	section_index = symbol->st_shndx;
	if (section_index >= view->ehdr->e_shnum ||
	    sections[section_index] == KPM_NO_OFFSET ||
	    symbol->st_value > view->sections[section_index].sh_size ||
	    symbol->st_size > view->sections[section_index].sh_size -
			      symbol->st_value)
		return -ENOEXEC;
	if ((unsigned long)module->image > (unsigned long)-1 -
					 sections[section_index] ||
	    (unsigned long)module->image + sections[section_index] >
					(unsigned long)-1 - symbol->st_value)
		return -EOVERFLOW;
	*address = (unsigned long)module->image +
		   sections[section_index] + symbol->st_value;
	return 0;
}

static int kpm_apply_relocations(const struct kpm_elf_view *view,
				 const size_t *sections,
				 struct kpm_module *module,
				 const struct kpm_image_layout *layout)
{
	struct kpm_arm64_plt_pool plt;
	unsigned int section_index;

	plt.words = layout->plt_count ?
		(u32 *)((char *)module->image + layout->plt_offset) : NULL;
	plt.address = (unsigned long)module->image + layout->plt_offset;
	plt.capacity = layout->plt_count;
	plt.used = 0;

	for (section_index = 1; section_index < view->ehdr->e_shnum;
	     section_index++) {
		const Elf64_Shdr *rela = &view->sections[section_index];
		const Elf64_Shdr *target;
		const Elf64_Rela *entries;
		size_t entry_count;
		size_t i;

		if (rela->sh_type != SHT_RELA)
			continue;
		target = &view->sections[rela->sh_info];
		if (!(target->sh_flags & SHF_ALLOC))
			continue;
		entries = (const Elf64_Rela *)(view->image + rela->sh_offset);
		entry_count = rela->sh_size / sizeof(*entries);
		for (i = 0; i < entry_count; i++) {
			const Elf64_Rela *entry = &entries[i];
			unsigned int type = ELF64_R_TYPE(entry->r_info);
			unsigned long symbol_address;
			unsigned long place_address;
			void *place;
			int width = kpm_relocation_width(type);
			int error;

			if (type == R_AARCH64_NONE)
				continue;
			if (sections[rela->sh_info] == KPM_NO_OFFSET ||
			    entry->r_offset > target->sh_size ||
			    width > target->sh_size - entry->r_offset)
				return -ENOEXEC;
			error = kpm_symbol_address(view, sections, module,
						   ELF64_R_SYM(entry->r_info),
						   &symbol_address);
			if (error)
				return error;
			if ((unsigned long)module->image > (unsigned long)-1 -
						 sections[rela->sh_info] ||
			    (unsigned long)module->image +
						 sections[rela->sh_info] >
						(unsigned long)-1 - entry->r_offset)
				return -EOVERFLOW;
			place_address = (unsigned long)module->image +
					sections[rela->sh_info] +
					entry->r_offset;
			place = (void *)place_address;
			error = kpm_arm64_apply_rela(place, place_address, type,
						     symbol_address, entry->r_addend,
						     &plt);
			if (error)
				return error;
		}
	}
	return 0;
}

static int kpm_is_executable_address(
	const struct kpm_elf_view *view, const size_t *sections,
	const struct kpm_module *module, unsigned long address)
{
	unsigned int index;

	for (index = 1; index < view->ehdr->e_shnum; index++) {
		const Elf64_Shdr *section = &view->sections[index];
		unsigned long start;

		if (!(section->sh_flags & SHF_EXECINSTR) ||
		    sections[index] == KPM_NO_OFFSET || !section->sh_size)
			continue;
		start = (unsigned long)module->image + sections[index];
		if (address >= start && address - start < section->sh_size)
			return 1;
	}
	return 0;
}

static int kpm_resolve_callbacks(const struct kpm_elf_view *view,
				 const size_t *sections,
				 struct kpm_module *module)
{
	u64 callback;

	memcpy(&callback,
	       (char *)module->image + sections[view->section_init],
	       sizeof(callback));
	if (!kpm_is_executable_address(
		    view, sections, module, (unsigned long)callback) ||
	    (callback & 3))
		return -ENOEXEC;
	module->init = (kpm_initcall_t)(unsigned long)callback;

	memcpy(&callback,
	       (char *)module->image + sections[view->section_exit],
	       sizeof(callback));
	if (!kpm_is_executable_address(
		    view, sections, module, (unsigned long)callback) ||
	    (callback & 3))
		return -ENOEXEC;
	module->exit = (kpm_exitcall_t)(unsigned long)callback;

	if (view->section_ctl0) {
		memcpy(&callback, (char *)module->image +
		       sections[view->section_ctl0], sizeof(callback));
		if (!kpm_is_executable_address(
			    view, sections, module, (unsigned long)callback) ||
		    (callback & 3))
			return -ENOEXEC;
		module->ctl0 = (kpm_ctl0call_t)(unsigned long)callback;
	}
	if (view->section_ctl1) {
		memcpy(&callback, (char *)module->image +
		       sections[view->section_ctl1], sizeof(callback));
		if (!kpm_is_executable_address(
			    view, sections, module, (unsigned long)callback) ||
		    (callback & 3))
			return -ENOEXEC;
		module->ctl1 = (kpm_ctl1call_t)(unsigned long)callback;
	}
	return 0;
}

static int kpm_load_image(struct kpm_module *module,
			  const struct kpm_elf_view *view)
{
	size_t *sections;
	struct kpm_image_layout layout;
	int error;

	sections = kcalloc(view->ehdr->e_shnum, sizeof(*sections), GFP_KERNEL);
	if (!sections)
		return -ENOMEM;
	error = kpm_layout_image(view, sections, &layout);
	if (error)
		goto out;
	module->image = kpm_alloc_image(layout.image_size);
	if (!module->image) {
		error = -ENOMEM;
		goto out;
	}
	module->image_size = layout.image_size;
	module->text_size = layout.text_size;
	module->ro_offset = layout.ro_offset;
	module->ro_size = layout.ro_size;
	module->data_offset = layout.data_offset;
	module->data_size = layout.data_size;
	module->text_pages = layout.text_size >> PAGE_SHIFT;
	module->total_pages = layout.image_size >> PAGE_SHIFT;
	error = set_memory_nx((unsigned long)module->image,
			      module->total_pages);
	if (error)
		goto out;

	error = kpm_elf_materialize(view, sections, layout.image_size,
				    module->image);
	if (error)
		goto out;
	error = kpm_apply_relocations(view, sections, module, &layout);
	if (error)
		goto out;
	error = kpm_resolve_callbacks(view, sections, module);
	if (error)
		goto out;
	flush_icache_range((unsigned long)module->image,
			   (unsigned long)module->image + module->text_size);
	error = kpm_set_image_permissions(module);
	if (error)
		goto out;

out:
	kfree(sections);
	return error;
}

static struct kpm_module *kpm_find_module_locked(const char *name)
{
	struct kpm_module *module;

	list_for_each_entry(module, &kpm_modules, node) {
		if (!strcmp(module->name, name))
			return module;
	}
	return NULL;
}

static struct kpm_module *kpm_get_live_module(const char *name)
{
	struct kpm_module *module;

	mutex_lock(&kpm_modules_lock);
	module = kpm_find_module_locked(name);
	if (module && module->state == KPM_MODULE_LIVE)
		atomic_inc(&module->active_calls);
	else
		module = NULL;
	mutex_unlock(&kpm_modules_lock);
	return module;
}

void kpm_module_put(struct kpm_module *module)
{
	if (atomic_dec_and_test(&module->active_calls))
		wake_up_all(&module->active_wait);
}

bool kpm_module_try_get_rcu(struct kpm_module *module)
{
	if (!module || READ_ONCE(module->state) != KPM_MODULE_LIVE)
		return false;
	atomic_inc(&module->active_calls);
	smp_mb__after_atomic();
	if (READ_ONCE(module->state) == KPM_MODULE_LIVE)
		return true;
	kpm_module_put(module);
	return false;
}

static long kpm_run_init(struct kpm_module *module)
{
	long result;

	mutex_lock(&kpm_callback_lock);
	WRITE_ONCE(kpm_callback_task, current);
	WRITE_ONCE(kpm_callback_module, module);
	result = module->init(module->args, "load", NULL);
	WRITE_ONCE(kpm_callback_module, NULL);
	WRITE_ONCE(kpm_callback_task, NULL);
	mutex_unlock(&kpm_callback_lock);
	return result;
}

static long kpm_run_exit(struct kpm_module *module)
{
	long result;

	mutex_lock(&kpm_callback_lock);
	WRITE_ONCE(kpm_callback_task, current);
	WRITE_ONCE(kpm_callback_module, module);
	result = module->exit(NULL);
	WRITE_ONCE(kpm_callback_module, NULL);
	WRITE_ONCE(kpm_callback_task, NULL);
	mutex_unlock(&kpm_callback_lock);
	return result;
}

static long kpm_run_ctl0(struct kpm_module *module, const char *args,
			 char __user *out_msg, int outlen)
{
	long result;

	mutex_lock(&kpm_callback_lock);
	WRITE_ONCE(kpm_callback_task, current);
	WRITE_ONCE(kpm_callback_module, module);
	result = module->ctl0(args, out_msg, outlen);
	WRITE_ONCE(kpm_callback_module, NULL);
	WRITE_ONCE(kpm_callback_task, NULL);
	mutex_unlock(&kpm_callback_lock);
	return result;
}

static long kpm_run_ctl1(struct kpm_module *module, void *arg1,
			 void *arg2, void *arg3)
{
	long result;

	mutex_lock(&kpm_callback_lock);
	WRITE_ONCE(kpm_callback_task, current);
	WRITE_ONCE(kpm_callback_module, module);
	result = module->ctl1(arg1, arg2, arg3);
	WRITE_ONCE(kpm_callback_module, NULL);
	WRITE_ONCE(kpm_callback_task, NULL);
	mutex_unlock(&kpm_callback_lock);
	return result;
}
struct kpm_module *kpm_current_module(void)
{
	if (READ_ONCE(kpm_callback_task) != current)
		return NULL;
	return READ_ONCE(kpm_callback_module);
}

static void kpm_free_module(struct kpm_module *module)
{
	kpm_free_image(module);
	kfree(module);
}

static void kpm_remove_module(struct kpm_module *module)
{
	mutex_lock(&kpm_modules_lock);
	if (!list_empty(&module->node))
		list_del_init(&module->node);
	mutex_unlock(&kpm_modules_lock);
}

static int kpm_read_module(const char *path, void **elf_image,
			   size_t *elf_size, struct kpm_elf_view *view)
{
	int error;

	error = kpm_read_file(path, elf_image, elf_size);
	if (error)
		return error;
	error = kpm_elf_parse(*elf_image, *elf_size, view);
	if (error) {
		vfree(*elf_image);
		*elf_image = NULL;
	}
	return error;
}

int kpm_load_path(const char *path, const char *args)
{
	struct kpm_elf_view view;
	struct kpm_module *module;
	void *elf_image = NULL;
	size_t elf_size = 0;
	long init_result;
	int error;

	if (!path || !path[0] || !args)
		return -EINVAL;
	error = kpm_read_module(path, &elf_image, &elf_size, &view);
	if (error)
		return error;
	if (view.section_event) {
		error = -EOPNOTSUPP;
		goto out_elf;
	}
	module = kzalloc(sizeof(*module), GFP_KERNEL);
	if (!module) {
		error = -ENOMEM;
		goto out_elf;
	}
	INIT_LIST_HEAD(&module->node);
	INIT_LIST_HEAD(&module->owned_patches);
	mutex_init(&module->control_lock);
	atomic_set(&module->active_calls, 0);
	init_waitqueue_head(&module->active_wait);
	module->state = KPM_MODULE_LOADING;
	strlcpy(module->args, args, sizeof(module->args));
	error = kpm_parse_metadata(module, &view);
	if (error)
		goto out_module;

	mutex_lock(&kpm_modules_lock);
	if (kpm_find_module_locked(module->name)) {
		mutex_unlock(&kpm_modules_lock);
		error = -EEXIST;
		goto out_module;
	}
	list_add_tail(&module->node, &kpm_modules);
	mutex_unlock(&kpm_modules_lock);

	error = kpm_load_image(module, &view);
	if (error)
		goto out_registered;
	init_result = kpm_run_init(module);
	if (init_result) {
		error = init_result < INT_MIN || init_result > INT_MAX ?
			-EOVERFLOW : (int)init_result;
		WRITE_ONCE(module->init_failed, true);
		mutex_lock(&kpm_modules_lock);
		module->state = KPM_MODULE_FAILED;
		mutex_unlock(&kpm_modules_lock);
		kpm_hook_remove_owner(module);
		pr_err("kpm: init of %s failed; retaining image\n",
		       module->name);
		goto out_elf;
	}
	module->init_succeeded = true;
	if (READ_ONCE(module->ever_patched))
		pr_warn("kpm: %s uses hotpatch; unload will be refused\n",
			module->name);
	pr_info("kpm: loaded %s (%s)\n", module->name, module->version);
	mutex_lock(&kpm_modules_lock);
	module->state = KPM_MODULE_LIVE;
	mutex_unlock(&kpm_modules_lock);
	vfree(elf_image);
	return 0;
out_registered:
	kpm_remove_module(module);
	kpm_free_image(module);
out_module:
	kfree(module);
out_elf:
	vfree(elf_image);
	return error;
}

int kpm_unload(const char *name)
{
	struct kpm_module *module;
	long exit_result;
	int error;

	if (!name || !name[0])
		return -EINVAL;
	mutex_lock(&kpm_modules_lock);
	module = kpm_find_module_locked(name);
	if (!module) {
		mutex_unlock(&kpm_modules_lock);
		return -ENOENT;
	}
	if (READ_ONCE(module->init_failed)) {
		mutex_unlock(&kpm_modules_lock);
		pr_warn("kpm: refusing unload after failed init of %s\n", name);
		return -EBUSY;
	}
	if (READ_ONCE(module->exit_failed)) {
		mutex_unlock(&kpm_modules_lock);
		pr_warn("kpm: refusing retry unload after failed exit of %s\n",
			name);
		return -EBUSY;
	}
	if (READ_ONCE(module->ever_patched)) {
		mutex_unlock(&kpm_modules_lock);
		pr_warn("kpm: refusing unload of hotpatched module %s\n", name);
		return -EBUSY;
	}
	if (module->state == KPM_MODULE_LOADING ||
	    module->state == KPM_MODULE_UNLOADING) {
		mutex_unlock(&kpm_modules_lock);
		return -EBUSY;
	}
	module->state = KPM_MODULE_UNLOADING;
	mutex_unlock(&kpm_modules_lock);

	synchronize_rcu();
	wait_event(module->active_wait, !atomic_read(&module->active_calls));
	if (READ_ONCE(module->ever_patched)) {
		mutex_lock(&kpm_modules_lock);
		module->state = KPM_MODULE_LIVE;
		mutex_unlock(&kpm_modules_lock);
		pr_warn("kpm: refusing unload of hotpatched module %s\n", name);
		return -EBUSY;
	}
	if (module->init_succeeded && !module->exit_called) {
		module->exit_called = true;
		exit_result = kpm_run_exit(module);
		if (exit_result) {
			error = exit_result < INT_MIN || exit_result > INT_MAX ?
				-EOVERFLOW : (int)exit_result;
			WRITE_ONCE(module->exit_failed, true);
			pr_err("kpm: exit of %s failed; retaining image\n",
			       module->name);
			goto failed;
		}
	}
	kpm_hook_remove_owner(module);
	pr_info("kpm: unloaded %s\n", module->name);
	kpm_remove_module(module);
	kpm_free_module(module);
	return 0;

failed:
	mutex_lock(&kpm_modules_lock);
	module->state = KPM_MODULE_FAILED;
	mutex_unlock(&kpm_modules_lock);
	return error;
}

int kpm_num(void)
{
	struct kpm_module *module;
	int count = 0;

	mutex_lock(&kpm_modules_lock);
	list_for_each_entry(module, &kpm_modules, node) {
		if (module->state == KPM_MODULE_LIVE) {
			if (count == INT_MAX) {
				count = -EOVERFLOW;
				break;
			}
			count++;
		}
	}
	mutex_unlock(&kpm_modules_lock);
	return count;
}

int kpm_list(char *buffer, size_t size, size_t *written)
{
	struct kpm_module *module;
	size_t used = 0;
	int error = 0;

	if (!buffer || !size || !written)
		return -EINVAL;
	mutex_lock(&kpm_modules_lock);
	list_for_each_entry(module, &kpm_modules, node) {
		size_t name_length;

		if (module->state != KPM_MODULE_LIVE)
			continue;
		name_length = strlen(module->name);
		if (used >= size || name_length + 1 > size - used - 1) {
			error = -ENOSPC;
			break;
		}
		memcpy(buffer + used, module->name, name_length);
		used += name_length;
		buffer[used++] = '\n';
	}
	if (!error) {
		buffer[used] = '\0';
		*written = used;
	}
	mutex_unlock(&kpm_modules_lock);
	return error;
}

int kpm_info(const char *name, char *buffer, size_t size, size_t *written)
{
	struct kpm_module *module;
	int length;

	if (!name || !buffer || !size || !written)
		return -EINVAL;
	module = kpm_get_live_module(name);
	if (!module)
		return -ENOENT;
	length = snprintf(buffer, size,
			  "name=%s\nversion=%s\nlicense=%s\nauthor=%s\n"
			  "description=%s\nargs=%s\n",
			  module->name, module->version, module->license,
			  module->author, module->description, module->args);
	kpm_module_put(module);
	if (length < 0)
		return length;
	if ((size_t)length >= size)
		return -ENOSPC;
	*written = length;
	return 0;
}

int kpm_control(const char *name, const char *args)
{
	return kpm_control_ex(name, args, NULL, 0);
}

int kpm_control_ex(const char *name, const char *args,
		   char __user *out_msg, int outlen)
{
	struct kpm_module *module;
	long result;
	int error;

	if (!name || !name[0] || !args || outlen < 0 ||
	    (outlen && !out_msg))
		return -EINVAL;
	module = kpm_get_live_module(name);
	if (!module)
		return -ENOENT;
	if (!module->ctl0) {
		kpm_module_put(module);
		return -EOPNOTSUPP;
	}
	mutex_lock(&module->control_lock);
	result = kpm_run_ctl0(module, args, out_msg, outlen);
	mutex_unlock(&module->control_lock);
	kpm_module_put(module);
	if (result < INT_MIN || result > INT_MAX)
		return -EOVERFLOW;
	error = (int)result;
	return error;
}

int kpm_control1(const char *name, void *arg1, void *arg2, void *arg3)
{
	struct kpm_module *module;
	long result;

	if (!name || !name[0])
		return -EINVAL;
	module = kpm_get_live_module(name);
	if (!module)
		return -ENOENT;
	if (!module->ctl1) {
		kpm_module_put(module);
		return -ENOSYS;
	}
	mutex_lock(&module->control_lock);
	result = kpm_run_ctl1(module, arg1, arg2, arg3);
	mutex_unlock(&module->control_lock);
	kpm_module_put(module);
	if (result < INT_MIN || result > INT_MAX)
		return -EOVERFLOW;
	return (int)result;
}

int kpm_version(char *buffer, size_t size, size_t *written)
{
	static const char version[] = KPM_VERSION_TEXT;
	size_t length = sizeof(version) - 1;

	if (!buffer || !written || !size)
		return -EINVAL;
	if (length >= size)
		return -ENOSPC;
	memcpy(buffer, version, sizeof(version));
	*written = length;
	return 0;
}
