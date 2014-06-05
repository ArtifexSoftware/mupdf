#include "pdf-interpret-imp.h"

static void
pdf_clean_stream_object(fz_context *ctx, pdf_document *doc, pdf_obj *obj, pdf_obj *orig_res, fz_cookie *cookie, int own_res)
{
	pdf_process process, process2;
	fz_buffer *buffer;
	int num;
	pdf_obj *res = NULL;
	pdf_obj *ref = NULL;

	if (!obj)
		return;

	fz_var(res);
	fz_var(ref);

	buffer = fz_new_buffer(ctx, 1024);

	fz_try(ctx)
	{
		if (own_res)
		{
			pdf_obj *r = pdf_dict_gets(ctx, obj, "Resources");
			if (r)
				orig_res = r;
		}

		res = pdf_new_dict(ctx, doc, 1);

		pdf_init_process_buffer(ctx, &process2, buffer);
		pdf_init_process_filter(ctx, &process, &process2, res);

		pdf_process_stream_object(ctx, doc, obj, &process, orig_res, cookie);

		num = pdf_to_num(ctx, obj);
		pdf_dict_dels(ctx, obj, "Filter");
		pdf_update_stream(ctx, doc, num, buffer);

		if (own_res)
		{
			ref = pdf_new_ref(ctx, doc, res);
			pdf_dict_puts(ctx, obj, "Resources", ref);
		}
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buffer);
		pdf_drop_obj(ctx, res);
		pdf_drop_obj(ctx, ref);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "Failed while cleaning xobject");
	}
}

static void
pdf_clean_type3(fz_context *ctx, pdf_document *doc, pdf_obj *obj, pdf_obj *orig_res, fz_cookie *cookie)
{
	pdf_process process, process2;
	fz_buffer *buffer;
	int num, i, l;
	pdf_obj *res = NULL;
	pdf_obj *ref = NULL;
	pdf_obj *charprocs;

	fz_var(res);
	fz_var(ref);

	fz_try(ctx)
	{
		res = pdf_dict_gets(ctx, obj, "Resources");
		if (res)
			orig_res = res;
		res = NULL;

		res = pdf_new_dict(ctx, doc, 1);

		charprocs = pdf_dict_gets(ctx, obj, "CharProcs");
		l = pdf_dict_len(ctx, charprocs);

		for (i = 0; i < l; i++)
		{
			pdf_obj *key = pdf_dict_get_key(ctx, charprocs, i);
			pdf_obj *val = pdf_dict_get_val(ctx, charprocs, i);

			buffer = fz_new_buffer(ctx, 1024);
			pdf_init_process_buffer(ctx, &process2, buffer);
			pdf_init_process_filter(ctx, &process, &process2, res);

			pdf_process_stream_object(ctx, doc, val, &process, orig_res, cookie);

			num = pdf_to_num(ctx, val);
			pdf_dict_dels(ctx, val, "Filter");
			pdf_update_stream(ctx, doc, num, buffer);
			pdf_dict_put(ctx, charprocs, key, val);
			fz_drop_buffer(ctx, buffer);
			buffer = NULL;
		}

		/* ProcSet - no cleaning possible. Inherit this from the old dict. */
		pdf_dict_puts(ctx, res, "ProcSet", pdf_dict_gets(ctx, orig_res, "ProcSet"));

		ref = pdf_new_ref(ctx, doc, res);
		pdf_dict_puts(ctx, obj, "Resources", ref);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buffer);
		pdf_drop_obj(ctx, res);
		pdf_drop_obj(ctx, ref);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "Failed while cleaning xobject");
	}
}

void pdf_clean_page_contents(fz_context *ctx, pdf_document *doc, pdf_page *page, fz_cookie *cookie, pdf_page_contents_process_fn *proc_fn, void *proc_arg)
{
	pdf_process process, process2;
	fz_buffer *buffer = fz_new_buffer(ctx, 1024);
	int num;
	pdf_obj *contents;
	pdf_obj *new_obj = NULL;
	pdf_obj *new_ref = NULL;
	pdf_obj *res = NULL;
	pdf_obj *ref = NULL;
	pdf_obj *obj;

	fz_var(new_obj);
	fz_var(new_ref);
	fz_var(res);
	fz_var(ref);

	fz_try(ctx)
	{
		res = pdf_new_dict(ctx, doc, 1);

		pdf_init_process_buffer(ctx, &process2, buffer);
		pdf_init_process_filter(ctx, &process, &process2, res);

		pdf_process_stream_object(ctx, doc, page->contents, &process, page->resources, cookie);

		contents = page->contents;
		if (pdf_is_array(ctx, contents))
		{
			int n = pdf_array_len(ctx, contents);
			int i;

			for (i = n-1; i > 0; i--)
				pdf_array_delete(ctx, contents, i);
			/* We cannot rewrite the 0th entry of contents
			 * directly as it may occur in other pages content
			 * dictionaries too. We therefore clone it and make
			 * a new object reference. */
			new_obj = pdf_copy_dict(ctx, pdf_array_get(ctx, contents, 0));
			new_ref = pdf_new_ref(ctx, doc, new_obj);
			num = pdf_to_num(ctx, new_ref);
			pdf_array_put(ctx, contents, 0, new_ref);
			pdf_dict_dels(ctx, new_obj, "Filter");
		}
		else
		{
			num = pdf_to_num(ctx, contents);
			pdf_dict_dels(ctx, contents, "Filter");
		}

		/* Now deal with resources. The spec allows for Type3 fonts and form
		 * XObjects to omit a resource dictionary and look in the parent.
		 * Avoid that by flattening here as part of the cleaning. This could
		 * conceivably cause changes in rendering, but we don't care. */

		/* ExtGState */
		obj = pdf_dict_gets(ctx, res, "ExtGState");
		if (obj)
		{
			int i, l;

			l = pdf_dict_len(ctx, obj);
			for (i = 0; i < l; i++)
			{
				pdf_obj *o = pdf_dict_gets(ctx, pdf_dict_get_val(ctx, obj, i), "SMask");

				if (!o)
					continue;
				o = pdf_dict_gets(ctx, o, "G");
				if (!o)
					continue;

				/* Transparency group XObject */
				pdf_clean_stream_object(ctx, doc, o, page->resources, cookie, 1);
			}
		}

		/* ColorSpace - no cleaning possible */

		/* Pattern */
		obj = pdf_dict_gets(ctx, res, "Pattern");
		if (obj)
		{
			int i, l;

			l = pdf_dict_len(ctx, obj);
			for (i = 0; i < l; i++)
			{
				pdf_obj *pat = pdf_dict_get_val(ctx, obj, i);

				if (!pat)
					continue;
				if (pdf_to_int(ctx, pdf_dict_gets(ctx, pat, "PatternType")) == 1)
					pdf_clean_stream_object(ctx, doc, pat, page->resources, cookie, 0);
			}
		}

		/* Shading - no cleaning possible */

		/* XObject */
		obj = pdf_dict_gets(ctx, res, "XObject");
		if (obj)
		{
			int i, l;

			l = pdf_dict_len(ctx, obj);
			for (i = 0; i < l; i++)
			{
				pdf_obj *xobj = pdf_dict_get_val(ctx, obj, i);

				if (strcmp(pdf_to_name(ctx, pdf_dict_gets(ctx, xobj, "Subtype")), "Form"))
					continue;

				pdf_clean_stream_object(ctx, doc, xobj, page->resources, cookie, 1);
			}
		}

		/* Font */
		obj = pdf_dict_gets(ctx, res, "Font");
		if (obj)
		{
			int i, l;

			l = pdf_dict_len(ctx, obj);
			for (i = 0; i < l; i++)
			{
				pdf_obj *o = pdf_dict_get_val(ctx, obj, i);

				if (!strcmp(pdf_to_name(ctx, pdf_dict_gets(ctx, o, "Subtype")), "Type3"))
				{
					pdf_clean_type3(ctx, doc, o, page->resources, cookie);
				}
			}
		}

		/* ProcSet - no cleaning possible. Inherit this from the old dict. */
		obj = pdf_dict_gets(ctx, page->resources, "ProcSet");
		if (obj)
			pdf_dict_puts(ctx, res, "ProcSet", obj);

		/* Properties - no cleaning possible. */

		if (proc_fn)
			(*proc_fn)(proc_arg, buffer, res);

		pdf_update_stream(ctx, doc, num, buffer);
		pdf_drop_obj(ctx, page->resources);
		ref = pdf_new_ref(ctx, doc, res);
		page->resources = pdf_keep_obj(ctx, ref);
		pdf_dict_puts(ctx, page->me, "Resources", ref);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buffer);
		pdf_drop_obj(ctx, new_obj);
		pdf_drop_obj(ctx, new_ref);
		pdf_drop_obj(ctx, res);
		pdf_drop_obj(ctx, ref);
	}
	fz_catch(ctx)
	{
		fz_rethrow_message(ctx, "Failed while cleaning page");
	}
}
