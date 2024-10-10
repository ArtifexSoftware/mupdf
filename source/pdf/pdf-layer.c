// Copyright (C) 2004-2021 Artifex Software, Inc.
//
// This file is part of MuPDF.
//
// MuPDF is free software: you can redistribute it and/or modify it under the
// terms of the GNU Affero General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
//
// MuPDF is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
// details.
//
// You should have received a copy of the GNU Affero General Public License
// along with MuPDF. If not, see <https://www.gnu.org/licenses/agpl-3.0.en.html>
//
// Alternative licensing terms are available from the licensor.
// For commercial licensing, see <https://www.artifex.com/> or contact
// Artifex Software, Inc., 39 Mesa Street, Suite 108A, San Francisco,
// CA 94129, USA, for further information.

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include <string.h>

/*
	Notes on OCGs etc.

	PDF Documents may contain Optional Content Groups. Which of
	these is shown at any given time is dependent on which
	Optional Content Configuration Dictionary is in force at the
	time.

	A pdf_document, once loaded, contains some state saying which
	OCGs are enabled/disabled, and which 'Intent' (or 'Intents')
	a file is being used for. This information is held outside of
	the actual PDF file.

	An Intent (just 'View' or 'Design' or 'All', according to
	PDF 2.0, but theoretically more) says which OCGs to consider
	or ignore in calculating the visibility of content. The
	Intent (or Intents, for there can be an array) is set by the
	current OCCD.

	When first loaded, we turn all OCGs on, then load the default
	OCCD. This may turn some OCGs off, and sets the document Intent.

	Callers can ask how many OCCDs there are, read the names/creators
	for each, and then select any one of them. That updates which
	OCGs are selected, and resets the Intent.

	Once an OCCD has been selected, a caller can enumerate the
	'displayable configuration'. This is a list of labels/radio
	buttons/check buttons that can be used to enable/disable
	given OCGs. The caller can then enable/disable OCGs by
	asking to select (or toggle) given entries in that list.

	Thus the handling of radio button groups, and 'locked'
	elements is kept within the core of MuPDF.

	Finally, the caller can set the 'usage' for a document. This
	can be 'View', 'Print', or 'Export'.
*/

typedef struct
{
	pdf_obj *obj;
	int n;
	int state;
} pdf_ocg_entry;

typedef struct
{
	int ocg;
	const char *name;
	int depth;
	unsigned int button_flags : 2;
	unsigned int locked : 1;
} pdf_ocg_ui;

struct pdf_ocg_descriptor
{
	int current;
	int num_configs;

	int len;
	pdf_ocg_entry *ocgs;

	pdf_obj *intent;
	const char *usage;

	int num_ui_entries;
	pdf_ocg_ui *ui;
};

typedef struct ve_stack
{
	pdf_obj **items;
	int count;
	int capacity;
} ve_stack;

static int pdf_is_ve_hidden(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, const char *usage, pdf_obj *ve, pdf_cycle_list *cycle_up, ve_stack *stack);

static ve_stack *ve_new_stack(fz_context *ctx, int initial_capacity)
{
	ve_stack* tbr = fz_malloc_struct(ctx, ve_stack);
	tbr->count = 0;
	tbr->items = fz_malloc_array(ctx, initial_capacity, pdf_obj*);
	tbr->capacity = initial_capacity;
	return tbr;
}

static void ve_stack_pop(ve_stack *stack)
{
	if (stack->count > 0)
	{
		stack->count--;
	}
}

static void ve_stack_push(fz_context *ctx, ve_stack *stack, pdf_obj *item)
{
	if (stack->count >= stack->capacity)
	{
		int newCapacity = stack->capacity * 2;
		stack->items = fz_realloc(ctx, stack->items, sizeof(pdf_obj*) * newCapacity);
		stack->capacity = newCapacity;
	}

	stack->items[stack->count] = item;
	stack->count++;
}

static int ve_stack_contains(fz_context *ctx, pdf_obj *item, ve_stack *stack)
{
	for (int i = 0; i < stack->count; i++)
	{
		if (!pdf_objcmp(ctx, item, stack->items[i]))
		{
			return 1;
		}
	}

	return 0;
}

static void ve_stack_free(fz_context *ctx, ve_stack *stack)
{
	fz_free(ctx, stack->items);
	fz_free(ctx, stack);
}

int
pdf_count_layer_configs(fz_context *ctx, pdf_document *doc)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	return desc ? desc->num_configs : 0;
}

int
pdf_count_layers(fz_context *ctx, pdf_document *doc)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	return desc ? desc->len : 0;
}

const char *
pdf_layer_name(fz_context *ctx, pdf_document *doc, int layer)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	return desc ? pdf_dict_get_text_string(ctx, desc->ocgs[layer].obj, PDF_NAME(Name)) : NULL;
}

int
pdf_layer_is_enabled(fz_context *ctx, pdf_document *doc, int layer)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	return desc ? desc->ocgs[layer].state : 0;
}

void
pdf_enable_layer(fz_context *ctx, pdf_document *doc, int layer, int enabled)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	if (desc)
		desc->ocgs[layer].state = enabled;
}

static int
count_entries(fz_context *ctx, pdf_obj *obj, pdf_cycle_list *cycle_up)
{
	pdf_cycle_list cycle;
	int len = pdf_array_len(ctx, obj);
	int i;
	int count = 0;

	for (i = 0; i < len; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		if (pdf_cycle(ctx, &cycle, cycle_up, o))
			continue;
		count += (pdf_is_array(ctx, o) ? count_entries(ctx, o, &cycle) : 1);
	}
	return count;
}

static pdf_ocg_ui *
get_ocg_ui(fz_context *ctx, pdf_ocg_descriptor *desc, int fill)
{
	if (fill == desc->num_ui_entries)
	{
		/* Number of layers changed while parsing;
		 * probably due to a repair. */
		int newsize = desc->num_ui_entries * 2;
		if (newsize == 0)
			newsize = 4; /* Arbitrary non-zero */
		desc->ui = fz_realloc_array(ctx, desc->ui, newsize, pdf_ocg_ui);
		desc->num_ui_entries = newsize;
	}
	return &desc->ui[fill];
}

static int
ocgcmp(const void *a_, const void *b_)
{
	const pdf_ocg_entry *a = a_;
	const pdf_ocg_entry *b = b_;

	return (b->n - a->n);
}

int
find_ocg(fz_context *ctx, pdf_ocg_descriptor *desc, pdf_obj *obj)
{
	int n = pdf_to_num(ctx, obj);
	int l = 0;
	int r = desc->len-1;

	if (n <= 0)
		return -1;

	while (l <= r)
	{
		int m = (l + r) >> 1;
		int c = desc->ocgs[m].n - n;
		if (c < 0)
			r = m - 1;
		else if (c > 0)
			l = m + 1;
		else
			return m;
	}
	return -1;
}

static int
find_rbgroup(fz_context *ctx, pdf_obj *ocg, pdf_obj *rbgroups)
{
	int len = pdf_array_len(ctx, rbgroups);

	for (int i = 0; i < len; i++)
	{
		pdf_obj *group = pdf_array_get(ctx, rbgroups, i);
		int len2 = pdf_array_len(ctx, group);

		for (int j = 0; j < len2; j++)
		{
			pdf_obj *item = pdf_array_get(ctx, group, j);
			if (!pdf_objcmp(ctx, item, ocg))
				return i;
		}
	}

	return -1;
}

static int
populate_ui(fz_context *ctx, pdf_ocg_descriptor *desc, int fill, pdf_obj *order, int depth, pdf_obj *rbgroups, pdf_obj *locked,
	pdf_cycle_list *cycle_up)
{
	pdf_cycle_list cycle;
	int len = pdf_array_len(ctx, order);
	int i, j;
	pdf_ocg_ui *ui;

	for (i = 0; i < len; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, order, i);
		if (pdf_is_array(ctx, o))
		{
			if (pdf_cycle(ctx, &cycle, cycle_up, o))
				continue;

			fill = populate_ui(ctx, desc, fill, o, depth+1, rbgroups, locked, &cycle);
			continue;
		}
		if (pdf_is_string(ctx, o))
		{
			ui = get_ocg_ui(ctx, desc, fill++);
			ui->depth = depth;
			ui->ocg = -1;
			ui->name = pdf_to_text_string(ctx, o);
			ui->button_flags = PDF_LAYER_UI_LABEL;
			ui->locked = 1;
			continue;
		}

		j = find_ocg(ctx, desc, o);
		if (j < 0)
			continue; /* OCG not found in main list! Just ignore it */
		ui = get_ocg_ui(ctx, desc, fill++);
		ui->depth = depth;
		ui->ocg = j;
		ui->name = pdf_dict_get_text_string(ctx, o, PDF_NAME(Name));
		ui->button_flags = find_rbgroup(ctx, o, rbgroups) >= 0 ? PDF_LAYER_UI_RADIOBOX : PDF_LAYER_UI_CHECKBOX;
		ui->locked = pdf_array_contains(ctx, o, locked);
	}
	return fill;
}

static void
drop_ui(fz_context *ctx, pdf_ocg_descriptor *desc)
{
	if (!desc)
		return;

	fz_free(ctx, desc->ui);
	desc->ui = NULL;
}

static void
load_ui(fz_context *ctx, pdf_ocg_descriptor *desc, pdf_obj *ocprops, pdf_obj *occg)
{
	pdf_obj *order;
	pdf_obj *rbgroups;
	pdf_obj *locked;
	int count;

	/* Count the number of entries */
	order = pdf_dict_get(ctx, occg, PDF_NAME(Order));
	if (!order)
		order = pdf_dict_getp(ctx, ocprops, "D/Order");
	count = count_entries(ctx, order, NULL);
	rbgroups = pdf_dict_get(ctx, occg, PDF_NAME(RBGroups));
	if (!rbgroups)
		rbgroups = pdf_dict_getp(ctx, ocprops, "D/RBGroups");
	locked = pdf_dict_get(ctx, occg, PDF_NAME(Locked));

	desc->num_ui_entries = count;
	if (desc->num_ui_entries == 0)
		return;

	desc->ui = fz_malloc_struct_array(ctx, count, pdf_ocg_ui);
	fz_try(ctx)
	{
		desc->num_ui_entries = populate_ui(ctx, desc, 0, order, 0, rbgroups, locked, NULL);
	}
	fz_catch(ctx)
	{
		drop_ui(ctx, desc);
		fz_rethrow(ctx);
	}
}

void
pdf_select_default_layer_config(fz_context *ctx, pdf_document *doc)
{
	pdf_ocg_descriptor *desc;
	int i, j, len, len2;
	pdf_obj *obj, *cobj;
	pdf_obj *name;

	desc = pdf_read_ocg(ctx, doc);

	obj = pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root)), PDF_NAME(OCProperties));
	if (!obj)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Unknown Layer config (None known!)");

	cobj = pdf_dict_get(ctx, obj, PDF_NAME(D));
	if (!cobj)
		fz_throw(ctx, FZ_ERROR_FORMAT, "No default Layer config");

	pdf_drop_obj(ctx, desc->intent);
	desc->intent = pdf_keep_obj(ctx, pdf_dict_get(ctx, cobj, PDF_NAME(Intent)));

	len = desc->len;
	name = pdf_dict_get(ctx, cobj, PDF_NAME(BaseState));
	if (pdf_name_eq(ctx, name, PDF_NAME(Unchanged)))
	{
		/* Do nothing */
	}
	else if (pdf_name_eq(ctx, name, PDF_NAME(OFF)))
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 0;
		}
	}
	else /* Default to ON */
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 1;
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME(ON));
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		for (j=0; j < len; j++)
		{
			if (!pdf_objcmp(ctx, desc->ocgs[j].obj, o))
			{
				desc->ocgs[j].state = 1;
				break;
			}
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME(OFF));
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		for (j=0; j < len; j++)
		{
			if (!pdf_objcmp(ctx, desc->ocgs[j].obj, o))
			{
				desc->ocgs[j].state = 0;
				break;
			}
		}
	}

	desc->current = -1;

	drop_ui(ctx, desc);
	load_ui(ctx, desc, obj, cobj);
}

void
pdf_select_layer_config(fz_context *ctx, pdf_document *doc, int config)
{
	pdf_ocg_descriptor *desc;
	int i, j, len, len2;
	pdf_obj *obj, *cobj;
	pdf_obj *name;

	if (config == -1)
	{
		pdf_select_default_layer_config(ctx, doc);
		return;
	}

	desc = pdf_read_ocg(ctx, doc);

	obj = pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root)), PDF_NAME(OCProperties));
	if (!obj)
	{
		if (config == 0)
			return;
		else
			fz_throw(ctx, FZ_ERROR_ARGUMENT, "Unknown Layer config (None known!)");
	}

	cobj = pdf_array_get(ctx, pdf_dict_get(ctx, obj, PDF_NAME(Configs)), config);
	if (!cobj)
	{
		if (config != 0)
			fz_throw(ctx, FZ_ERROR_ARGUMENT, "Illegal Layer config");
		cobj = pdf_dict_get(ctx, obj, PDF_NAME(D));
		if (!cobj)
			fz_throw(ctx, FZ_ERROR_FORMAT, "No default Layer config");
	}

	pdf_drop_obj(ctx, desc->intent);
	desc->intent = pdf_keep_obj(ctx, pdf_dict_get(ctx, cobj, PDF_NAME(Intent)));

	len = desc->len;
	name = pdf_dict_get(ctx, cobj, PDF_NAME(BaseState));
	if (pdf_name_eq(ctx, name, PDF_NAME(Unchanged)))
	{
		/* Do nothing */
	}
	else if (pdf_name_eq(ctx, name, PDF_NAME(OFF)))
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 0;
		}
	}
	else /* Default to ON */
	{
		for (i = 0; i < len; i++)
		{
			desc->ocgs[i].state = 1;
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME(ON));
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		for (j=0; j < len; j++)
		{
			if (!pdf_objcmp(ctx, desc->ocgs[j].obj, o))
			{
				desc->ocgs[j].state = 1;
				break;
			}
		}
	}

	obj = pdf_dict_get(ctx, cobj, PDF_NAME(OFF));
	len2 = pdf_array_len(ctx, obj);
	for (i = 0; i < len2; i++)
	{
		pdf_obj *o = pdf_array_get(ctx, obj, i);
		for (j=0; j < len; j++)
		{
			if (!pdf_objcmp(ctx, desc->ocgs[j].obj, o))
			{
				desc->ocgs[j].state = 0;
				break;
			}
		}
	}

	desc->current = config;

	drop_ui(ctx, desc);
	load_ui(ctx, desc, obj, cobj);
}

void
pdf_default_layer_config_info(fz_context *ctx, pdf_document *doc, pdf_layer_config *info)
{
	pdf_obj *ocprops;
	pdf_obj *obj;

	if (!info)
		return;

	info->name = NULL;
	info->creator = NULL;

	ocprops = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/OCProperties");
	if (!ocprops)
		return;

	obj = pdf_dict_get(ctx, ocprops, PDF_NAME(D));
	if (!obj)
		return;

	info->creator = pdf_dict_get_string(ctx, obj, PDF_NAME(Creator), NULL);
	info->name = pdf_dict_get_string(ctx, obj, PDF_NAME(Name), NULL);
}

void
pdf_layer_config_info(fz_context *ctx, pdf_document *doc, int config_num, pdf_layer_config *info)
{
	pdf_ocg_descriptor *desc;
	pdf_obj *ocprops;
	pdf_obj *obj;

	if (config_num == -1)
	{
		pdf_default_layer_config_info(ctx, doc, info);
		return;
	}

	if (!info)
		return;

	desc = pdf_read_ocg(ctx, doc);

	info->name = NULL;
	info->creator = NULL;

	if (config_num < 0 || config_num >= desc->num_configs)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Invalid layer config number");

	ocprops = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/OCProperties");
	if (!ocprops)
		return;

	obj = pdf_dict_get(ctx, ocprops, PDF_NAME(Configs));
	if (pdf_is_array(ctx, obj))
		obj = pdf_array_get(ctx, obj, config_num);
	else if (config_num == 0)
		obj = pdf_dict_get(ctx, ocprops, PDF_NAME(D));
	else
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Invalid layer config number");

	info->creator = pdf_dict_get_string(ctx, obj, PDF_NAME(Creator), NULL);
	info->name = pdf_dict_get_string(ctx, obj, PDF_NAME(Name), NULL);
}

void
pdf_drop_ocg(fz_context *ctx, pdf_document *doc)
{
	pdf_ocg_descriptor *desc;
	int i;

	if (!doc)
		return;
	desc = doc->ocg;
	if (!desc)
		return;

	drop_ui(ctx, desc);
	pdf_drop_obj(ctx, desc->intent);
	for (i = 0; i < desc->len; i++)
		pdf_drop_obj(ctx, desc->ocgs[i].obj);
	fz_free(ctx, desc->ocgs);
	fz_free(ctx, desc);
}

static void
clear_radio_group(fz_context *ctx, pdf_document *doc, pdf_obj *ocg)
{
	pdf_obj *group, *rbgroups;
	int i, j, k, len;

	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	if (!desc)
		return;

	rbgroups = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/OCProperties/D/RBGroups");

	i = find_rbgroup(ctx, ocg, rbgroups);
	if (i < 0)
		return;

	group = pdf_array_get(ctx, rbgroups, i);
	len = pdf_array_len(ctx, group);

	for (j = 0; j < len; j++)
	{
		pdf_obj *g = pdf_array_get(ctx, group, j);
		k = find_ocg(ctx, desc, g);
		doc->ocg->ocgs[k].state = 0;
	}
}

int pdf_count_layer_config_ui(fz_context *ctx, pdf_document *doc)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	return desc ? desc->num_ui_entries : 0;
}

void pdf_select_layer_config_ui(fz_context *ctx, pdf_document *doc, int ui)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	pdf_ocg_ui *entry;

	if (ui < 0 || ui >= desc->num_ui_entries)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Out of range UI entry selected");

	entry = &desc->ui[ui];
	if (entry->button_flags != PDF_LAYER_UI_RADIOBOX &&
		entry->button_flags != PDF_LAYER_UI_CHECKBOX)
		return;
	if (entry->locked)
		return;

	if (entry->button_flags == PDF_LAYER_UI_RADIOBOX)
		clear_radio_group(ctx, doc, desc->ocgs[entry->ocg].obj);

	desc->ocgs[entry->ocg].state = 1;
}

void pdf_toggle_layer_config_ui(fz_context *ctx, pdf_document *doc, int ui)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	pdf_ocg_ui *entry;
	int selected;

	if (ui < 0 || ui >= desc->num_ui_entries)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Out of range UI entry toggled");

	entry = &desc->ui[ui];
	if (entry->button_flags != PDF_LAYER_UI_RADIOBOX &&
		entry->button_flags != PDF_LAYER_UI_CHECKBOX)
		return;
	if (entry->locked)
		return;

	selected = desc->ocgs[entry->ocg].state;

	if (entry->button_flags == PDF_LAYER_UI_RADIOBOX)
		clear_radio_group(ctx, doc, desc->ocgs[entry->ocg].obj);

	desc->ocgs[entry->ocg].state = !selected;
}

void pdf_deselect_layer_config_ui(fz_context *ctx, pdf_document *doc, int ui)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	pdf_ocg_ui *entry;

	if (ui < 0 || ui >= desc->num_ui_entries)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Out of range UI entry deselected");

	entry = &desc->ui[ui];
	if (entry->button_flags != PDF_LAYER_UI_RADIOBOX &&
		entry->button_flags != PDF_LAYER_UI_CHECKBOX)
		return;
	if (entry->locked)
		return;

	desc->ocgs[entry->ocg].state = 0;
}

void
pdf_layer_config_ui_info(fz_context *ctx, pdf_document *doc, int ui, pdf_layer_config_ui *info)
{
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	pdf_ocg_ui *entry;

	if (!info)
		return;

	info->depth = 0;
	info->locked = 0;
	info->selected = 0;
	info->text = NULL;
	info->type = 0;

	if (ui < 0 || ui >= desc->num_ui_entries)
		fz_throw(ctx, FZ_ERROR_ARGUMENT, "Out of range UI entry selected");

	entry = &desc->ui[ui];
	info->type = entry->button_flags;
	info->depth = entry->depth;
	info->selected = desc->ocgs[entry->ocg].state;
	info->locked = entry->locked;
	info->text = entry->name;
}

static int
ocg_intents_include(fz_context *ctx, pdf_ocg_descriptor *desc, const char *name)
{
	int i, len;

	if (strcmp(name, "All") == 0)
		return 1;

	/* In the absence of a specified intent, it's 'View' */
	if (!desc->intent)
		return (strcmp(name, "View") == 0);

	if (pdf_is_name(ctx, desc->intent))
	{
		const char *intent = pdf_to_name(ctx, desc->intent);
		if (strcmp(intent, "All") == 0)
			return 1;
		return (strcmp(intent, name) == 0);
	}
	if (!pdf_is_array(ctx, desc->intent))
		return 0;

	len = pdf_array_len(ctx, desc->intent);
	for (i=0; i < len; i++)
	{
		const char *intent = pdf_array_get_name(ctx, desc->intent, i);
		if (strcmp(intent, "All") == 0)
			return 1;
		if (strcmp(intent, name) == 0)
			return 1;
	}
	return 0;
}

static int
pdf_is_ocg_hidden_imp(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, const char *usage, pdf_obj *ocg, pdf_cycle_list *cycle_up, ve_stack* stack)
{
	pdf_cycle_list cycle;
	pdf_ocg_descriptor *desc = pdf_read_ocg(ctx, doc);
	pdf_obj *obj, *obj2, *type;
	char event_state[16];

	/* If no usage, everything is visible */
	if (!usage)
		return 0;

	/* If no ocg descriptor or no ocgs described, everything is visible */
	if (!desc || desc->len == 0)
		return 0;

	/* If we've been handed a name, look it up in the properties. */
	if (pdf_is_name(ctx, ocg))
	{
		ocg = pdf_dict_get(ctx, pdf_dict_get(ctx, rdb, PDF_NAME(Properties)), ocg);
	}
	/* If we haven't been given an ocg at all, then we're visible */
	if (!ocg)
		return 0;

	/* Avoid infinite recursions */
	if (pdf_cycle(ctx, &cycle, cycle_up, ocg))
		return 0;

	fz_strlcpy(event_state, usage, sizeof event_state);
	fz_strlcat(event_state, "State", sizeof event_state);

	type = pdf_dict_get(ctx, ocg, PDF_NAME(Type));

	if (pdf_name_eq(ctx, type, PDF_NAME(OCG)))
	{
		/* An Optional Content Group */
		int default_value = 0;
		int len = desc->len;
		int i;
		pdf_obj *es;

		/* by default an OCG is visible, unless it's explicitly hidden */
		for (i = 0; i < len; i++)
		{
			/* Deliberately do NOT resolve here. Bug 702261. */
			if (!pdf_objcmp(ctx, desc->ocgs[i].obj, ocg))
			{
				default_value = !desc->ocgs[i].state;
				break;
			}
		}

		/* Check Intents; if our intent is not part of the set given
		 * by the current config, we should ignore it. */
		obj = pdf_dict_get(ctx, ocg, PDF_NAME(Intent));
		if (pdf_is_name(ctx, obj))
		{
			/* If it doesn't match, it's hidden */
			if (ocg_intents_include(ctx, desc, pdf_to_name(ctx, obj)) == 0)
				return 1;
		}
		else if (pdf_is_array(ctx, obj))
		{
			int match = 0;
			len = pdf_array_len(ctx, obj);
			for (i=0; i<len; i++) {
				match |= ocg_intents_include(ctx, desc, pdf_array_get_name(ctx, obj, i));
				if (match)
					break;
			}
			/* If we don't match any, it's hidden */
			if (match == 0)
				return 1;
		}
		else
		{
			/* If it doesn't match, it's hidden */
			if (ocg_intents_include(ctx, desc, "View") == 0)
				return 1;
		}

		/* FIXME: Currently we do a very simple check whereby we look
		 * at the Usage object (an Optional Content Usage Dictionary)
		 * and check to see if the corresponding 'event' key is on
		 * or off.
		 *
		 * Really we should only look at Usage dictionaries that
		 * correspond to entries in the AS list in the OCG config.
		 * Given that we don't handle Zoom or User, or Language
		 * dicts, this is not really a problem. */
		obj = pdf_dict_get(ctx, ocg, PDF_NAME(Usage));
		if (!pdf_is_dict(ctx, obj))
			return default_value;
		/* FIXME: Should look at Zoom (and return hidden if out of
		 * max/min range) */
		/* FIXME: Could provide hooks to the caller to check if
		 * User is appropriate - if not return hidden. */
		obj2 = pdf_dict_gets(ctx, obj, usage);
		es = pdf_dict_gets(ctx, obj2, event_state);
		if (pdf_name_eq(ctx, es, PDF_NAME(OFF)))
		{
			return 1;
		}
		if (pdf_name_eq(ctx, es, PDF_NAME(ON)))
		{
			return 0;
		}
		return default_value;
	}
	else if (pdf_name_eq(ctx, type, PDF_NAME(OCMD)))
	{
		/* An Optional Content Membership Dictionary */
		pdf_obj *name;
		int combine, on = 0;

		obj = pdf_dict_get(ctx, ocg, PDF_NAME(VE));
		if (pdf_is_array(ctx, obj))
		{
			int tbr, owns_stack = 0;
			if (!stack)
			{
				stack = ve_new_stack(ctx, 4);
				owns_stack = 1;
			}

			ve_stack_push(ctx, stack, ocg);
			tbr = pdf_is_ve_hidden(ctx, doc, rdb, usage, obj, cycle_up, stack);

			if (owns_stack)
				ve_stack_free(ctx, stack);
			else
				ve_stack_pop(stack);

			return tbr;
		}
		name = pdf_dict_get(ctx, ocg, PDF_NAME(P));
		/* Set combine; Bit 0 set => AND, Bit 1 set => true means
		 * Off, otherwise true means On */
		if (pdf_name_eq(ctx, name, PDF_NAME(AllOn)))
		{
			combine = 1;
		}
		else if (pdf_name_eq(ctx, name, PDF_NAME(AnyOff)))
		{
			combine = 2;
		}
		else if (pdf_name_eq(ctx, name, PDF_NAME(AllOff)))
		{
			combine = 3;
		}
		else /* Assume it's the default (AnyOn) */
		{
			combine = 0;
		}

		obj = pdf_dict_get(ctx, ocg, PDF_NAME(OCGs));
		on = combine & 1;
		if (pdf_is_array(ctx, obj)) {
			int i, len;
			len = pdf_array_len(ctx, obj);
			for (i = 0; i < len; i++)
			{
				int hidden = pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, pdf_array_get(ctx, obj, i), &cycle, stack);
				if (combine == 0 && !hidden)
				{
					on = 1;
					break;
				}
				else if (combine == 1 && hidden)
				{
					on = 0;
					break;
				}
				else if (combine == 2 && hidden)
				{
					on = 1;
					break;
				}
				else if (combine == 3 && !hidden)
				{
					on = 0;
					break;
				}
			}
		}
		else
		{
			on = pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, obj, &cycle, stack);
			if ((combine & 1) == 0)
				on = !on;
		}

		return !on;
	}
	/* No idea what sort of object this is - be visible */
	return 0;
}

static int pdf_is_ve_hidden(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, const char *usage, pdf_obj *ve, pdf_cycle_list *cycle_up, ve_stack* stack)
{
	pdf_obj *op, *item;
	int len;
	len = pdf_array_len(ctx, ve);

	if (len < 2)
		fz_throw(ctx, FZ_ERROR_FORMAT, "Invalid Visibility Expression");

	op = pdf_array_get(ctx, ve, 0);

	if (pdf_name_eq(ctx, op, PDF_NAME(Not)))
	{
		int tbr;

		if (len != 2)
			fz_throw(ctx, FZ_ERROR_FORMAT, "Invalid Visibility Expression");

		item = pdf_array_get(ctx, ve, 1);

		if (ve_stack_contains(ctx, item, stack))
		{
			fz_warn(ctx, "Circular reference in visibility expression!");
			return 0;
		}

		ve_stack_push(ctx, stack, item);

		if (!pdf_is_array(ctx, item))
		{
			tbr = !pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, item, cycle_up, stack);
		}
		else
		{
			tbr = !pdf_is_ve_hidden(ctx, doc, rdb, usage, item, cycle_up, stack);
		}

		ve_stack_pop(stack);

		return tbr;
	}
	else if (pdf_name_eq(ctx, op, PDF_NAME(And)))
	{
		int hidden, visible = 1;

		if (len < 3)
			fz_throw(ctx, FZ_ERROR_FORMAT, "Invalid Visibility Expression");

		for (int i = 1; i < len; i++)
		{
			item = pdf_array_get(ctx, ve, i);

			if (ve_stack_contains(ctx, item, stack))
			{
				fz_warn(ctx, "Circular reference in visibility expression!");
				return 0;
			}

			ve_stack_push(ctx, stack, item);

			if (!pdf_is_array(ctx, item))
			{
				hidden = pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, item, cycle_up, stack);
			}
			else
			{
				hidden = pdf_is_ve_hidden(ctx, doc, rdb, usage, item, cycle_up, stack);
			}

			ve_stack_pop(stack);

			if (hidden)
			{
				visible = 0;
				break;
			}
		}
		return !visible;
	}
	else if (pdf_name_eq(ctx, op, PDF_NAME(Or)))
	{
		int hidden, visible = 0;

		if (len < 3)
			fz_throw(ctx, FZ_ERROR_FORMAT, "Invalid Visibility Expression");

		for (int i = 1; i < len; i++)
		{
			item = pdf_array_get(ctx, ve, i);

			if (ve_stack_contains(ctx, item, stack))
			{
				fz_warn(ctx, "Circular reference in visibility expression!");
				return 0;
			}

			ve_stack_push(ctx, stack, item);

			if (!pdf_is_array(ctx, item))
			{
				hidden = pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, item, cycle_up, stack);
			}
			else
			{
				hidden = pdf_is_ve_hidden(ctx, doc, rdb, usage, item, cycle_up, stack);
			}

			ve_stack_pop(stack);

			if (!hidden)
			{
				visible = 1;
				break;
			}
		}
		return !visible;
	}
	else
	{
		fz_throw(ctx, FZ_ERROR_FORMAT, "Invalid Visibility Expression");
	}
}

int
pdf_is_ocg_hidden(fz_context *ctx, pdf_document *doc, pdf_obj *rdb, const char *usage, pdf_obj *ocg)
{
	return pdf_is_ocg_hidden_imp(ctx, doc, rdb, usage, ocg, NULL, NULL);
}

pdf_ocg_descriptor *
pdf_read_ocg(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *prop, *ocgs, *configs;
	int len, i, num_configs;

	if (doc->ocg)
		return doc->ocg;

	fz_try(ctx)
	{
		prop = pdf_dict_get(ctx, pdf_dict_get(ctx, pdf_trailer(ctx, doc), PDF_NAME(Root)), PDF_NAME(OCProperties));

		configs = pdf_dict_get(ctx, prop, PDF_NAME(Configs));
		num_configs = pdf_array_len(ctx, configs);
		ocgs = pdf_dict_get(ctx, prop, PDF_NAME(OCGs));
		len = pdf_array_len(ctx, ocgs);

		doc->ocg = fz_malloc_struct(ctx, pdf_ocg_descriptor);
		doc->ocg->ocgs = fz_calloc(ctx, len, sizeof(*doc->ocg->ocgs));
		doc->ocg->len = len;
		doc->ocg->num_configs = num_configs;

		for (i = 0; i < len; i++)
		{
			pdf_obj *o = pdf_array_get(ctx, ocgs, i);
			doc->ocg->ocgs[i].obj = pdf_keep_obj(ctx, o);
			doc->ocg->ocgs[i].n = pdf_to_num(ctx, o);
			doc->ocg->ocgs[i].state = 1;
		}
		qsort(doc->ocg->ocgs, len, sizeof(doc->ocg->ocgs[0]), ocgcmp);

		pdf_select_default_layer_config(ctx, doc);
	}
	fz_catch(ctx)
	{
		pdf_drop_ocg(ctx, doc);
		doc->ocg = NULL;
		fz_rethrow_if(ctx, FZ_ERROR_TRYLATER);
		fz_rethrow_if(ctx, FZ_ERROR_SYSTEM);
		fz_report_error(ctx);
		fz_warn(ctx, "Ignoring broken Optional Content configuration");
		doc->ocg = fz_malloc_struct(ctx, pdf_ocg_descriptor);
	}

	return doc->ocg;
}

void
pdf_set_layer_config_as_default(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *ocprops, *d, *order, *on, *configs, *rbgroups;
	int k;

	ocprops = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/OCProperties");
	if (!ocprops)
		return;

	/* All files with OCGs are required to have a D entry */
	d = pdf_dict_get(ctx, ocprops, PDF_NAME(D));
	if (d == NULL)
		return;

	pdf_dict_put(ctx, d, PDF_NAME(BaseState), PDF_NAME(OFF));

	/* We are about to delete RBGroups and Order, from D. These are
	 * both the underlying defaults for other configs, so copy the
	 * current values out to any config that doesn't have one
	 * already. */
	order = pdf_dict_get(ctx, d, PDF_NAME(Order));
	rbgroups = pdf_dict_get(ctx, d, PDF_NAME(RBGroups));
	configs = pdf_dict_get(ctx, ocprops, PDF_NAME(Configs));
	if (configs)
	{
		int len = pdf_array_len(ctx, configs);
		for (k=0; k < len; k++)
		{
			pdf_obj *config = pdf_array_get(ctx, configs, k);

			if (order && !pdf_dict_get(ctx, config, PDF_NAME(Order)))
				pdf_dict_put(ctx, config, PDF_NAME(Order), order);
			if (rbgroups && !pdf_dict_get(ctx, config, PDF_NAME(RBGroups)))
				pdf_dict_put(ctx, config, PDF_NAME(RBGroups), rbgroups);
		}
	}

	/* Offer all the layers in the UI */
	order = pdf_new_array(ctx, doc, 4);
	on = pdf_new_array(ctx, doc, 4);
	for (k = 0; k < doc->ocg->len; k++)
	{
		pdf_ocg_entry *s = &doc->ocg->ocgs[k];

		pdf_array_push(ctx, order, s->obj);
		if (s->state)
			pdf_array_push(ctx, on, s->obj);
	}
	pdf_dict_put(ctx, d, PDF_NAME(Order), order);
	pdf_dict_put(ctx, d, PDF_NAME(ON), on);
	pdf_dict_del(ctx, d, PDF_NAME(OFF));
	pdf_dict_del(ctx, d, PDF_NAME(AS));
	pdf_dict_put(ctx, d, PDF_NAME(Intent), PDF_NAME(View));
	pdf_dict_del(ctx, d, PDF_NAME(Name));
	pdf_dict_del(ctx, d, PDF_NAME(Creator));
	pdf_dict_del(ctx, d, PDF_NAME(RBGroups));
	pdf_dict_del(ctx, d, PDF_NAME(Locked));

	pdf_dict_del(ctx, ocprops, PDF_NAME(Configs));
}
