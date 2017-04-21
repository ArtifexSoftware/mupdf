#include "pdfapp.h"
#include "curl_stream.h"

#include <string.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>

#define BEYOND_THRESHHOLD 40
#ifndef PATH_MAX
#define PATH_MAX (1024)
#endif

#ifndef MAX
#define MAX(a,b) ((a) > (b) ? (a) : (b))
#endif

enum panning
{
	DONT_PAN = 0,
	PAN_TO_TOP,
	PAN_TO_BOTTOM
};

enum
{
	PDFAPP_OUTLINE_DEFERRED = 1,
	PDFAPP_OUTLINE_LOAD_NOW = 2
};

static void pdfapp_showpage(pdfapp_t *app, int loadpage, int drawpage, int repaint, int transition, int searching);
static void pdfapp_updatepage(pdfapp_t *app);

static const int zoomlist[] = { 18, 24, 36, 54, 72, 96, 120, 144, 180, 216, 288 };

static int zoom_in(int oldres)
{
	int i;
	for (i = 0; i < nelem(zoomlist) - 1; ++i)
		if (zoomlist[i] <= oldres && zoomlist[i+1] > oldres)
			return zoomlist[i+1];
	return zoomlist[i];
}

static int zoom_out(int oldres)
{
	int i;
	for (i = 0; i < nelem(zoomlist) - 1; ++i)
		if (zoomlist[i] < oldres && zoomlist[i+1] >= oldres)
			return zoomlist[i];
	return zoomlist[0];
}

static void pdfapp_warn(pdfapp_t *app, const char *fmt, ...)
{
	char buf[1024];
	va_list ap;
	va_start(ap, fmt);
	fz_vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	buf[sizeof(buf)-1] = 0;
	winwarn(app, buf);
}

static void pdfapp_error(pdfapp_t *app, char *msg)
{
	winerror(app, msg);
}

char *pdfapp_version(pdfapp_t *app)
{
	return
		"MuPDF " FZ_VERSION "\n"
		"Copyright 2006-2017 Artifex Software, Inc.\n";
}

char *pdfapp_usage(pdfapp_t *app)
{
	return
		"L\t\t-- rotate left\n"
		"R\t\t-- rotate right\n"
		"h\t\t-- scroll left\n"
		"j down\t\t-- scroll down\n"
		"k up\t\t-- scroll up\n"
		"l\t\t-- scroll right\n"
		"+\t\t-- zoom in\n"
		"-\t\t-- zoom out\n"
		"W\t\t-- zoom to fit window width\n"
		"H\t\t-- zoom to fit window height\n"
		"Z\t\t-- zoom to fit page\n"
		"[\t\t-- decrease font size (EPUB only)\n"
		"]\t\t-- increase font size (EPUB only)\n"
		"w\t\t-- shrinkwrap\n"
		"f\t\t-- fullscreen\n"
		"r\t\t-- reload file\n"
		". pgdn right spc\t-- next page\n"
		", pgup left b bkspc\t-- previous page\n"
		">\t\t-- next 10 pages\n"
		"<\t\t-- back 10 pages\n"
		"m\t\t-- mark page for snap back\n"
		"t\t\t-- pop back to latest mark\n"
		"1m\t\t-- mark page in register 1\n"
		"1t\t\t-- go to page in register 1\n"
		"G\t\t-- go to last page\n"
		"123g\t\t-- go to page 123\n"
		"/\t\t-- search forwards for text\n"
		"?\t\t-- search backwards for text\n"
		"n\t\t-- find next search result\n"
		"N\t\t-- find previous search result\n"
		"c\t\t-- toggle between color and grayscale\n"
		"i\t\t-- toggle inverted color mode\n"
		"q\t\t-- quit\n"
	;
}

void pdfapp_init(fz_context *ctx, pdfapp_t *app)
{
	memset(app, 0, sizeof(pdfapp_t));
	app->scrw = 640;
	app->scrh = 480;
	app->resolution = 72;
	app->ctx = ctx;

	app->layout_w = 450;
	app->layout_h = 600;
	app->layout_em = 12;
	app->layout_css = NULL;
	app->layout_use_doc_css = 1;

	app->transition.duration = 0.25;
	app->transition.type = FZ_TRANSITION_FADE;
#if defined(_WIN32) || defined(_WIN64)
	app->colorspace = fz_device_bgr(ctx);
#else
	app->colorspace = fz_device_rgb(ctx);
#endif
	app->tint_r = 255;
	app->tint_g = 250;
	app->tint_b = 240;
}

void pdfapp_setresolution(pdfapp_t *app, int res)
{
	app->resolution = res;
}

void pdfapp_invert(pdfapp_t *app, const fz_rect *rect)
{
	fz_irect b;
	fz_invert_pixmap_rect(app->ctx, app->image, fz_round_rect(&b, rect));
}

void pdfapp_reloadfile(pdfapp_t *app)
{
	char filename[PATH_MAX];
	fz_strlcpy(filename, app->docpath, PATH_MAX);
	pdfapp_close(app);
	pdfapp_open(app, filename, 1);
}

static void event_cb(fz_context *ctx, pdf_document *doc, pdf_doc_event *event, void *data)
{
	pdfapp_t *app = (pdfapp_t *)data;

	switch (event->type)
	{
	case PDF_DOCUMENT_EVENT_ALERT:
		{
			pdf_alert_event *alert = pdf_access_alert_event(ctx, event);
			winalert(app, alert);
		}
		break;

	case PDF_DOCUMENT_EVENT_PRINT:
		winprint(app);
		break;

	case PDF_DOCUMENT_EVENT_EXEC_MENU_ITEM:
		{
			const char *item = pdf_access_exec_menu_item_event(ctx, event);

			if (!strcmp(item, "Print"))
				winprint(app);
			else
				pdfapp_warn(app, "The document attempted to execute menu item: %s. (Not supported)", item);
		}
		break;

	case PDF_DOCUMENT_EVENT_EXEC_DIALOG:
		pdfapp_warn(app, "The document attempted to open a dialog box. (Not supported)");
		break;

	case PDF_DOCUMENT_EVENT_LAUNCH_URL:
		{
			pdf_launch_url_event *launch_url = pdf_access_launch_url_event(ctx, event);

			pdfapp_warn(app, "The document attempted to open url: %s. (Not supported by app)", launch_url->url);
		}
		break;

	case PDF_DOCUMENT_EVENT_MAIL_DOC:
		{
			pdf_mail_doc_event *mail_doc = pdf_access_mail_doc_event(ctx, event);

			pdfapp_warn(app, "The document attempted to mail the document%s%s%s%s%s%s%s%s (Not supported)",
				mail_doc->to[0]?", To: ":"", mail_doc->to,
				mail_doc->cc[0]?", Cc: ":"", mail_doc->cc,
				mail_doc->bcc[0]?", Bcc: ":"", mail_doc->bcc,
				mail_doc->subject[0]?", Subject: ":"", mail_doc->subject);
		}
		break;
	}
}

void pdfapp_open(pdfapp_t *app, char *filename, int reload)
{
	pdfapp_open_progressive(app, filename, reload, 0);
}

#ifdef HAVE_CURL
static void
pdfapp_more_data(void *app_, int complete)
{
	pdfapp_t *app = (pdfapp_t *)app_;

	if (complete && app->outline_deferred == PDFAPP_OUTLINE_DEFERRED)
	{
		app->outline_deferred = PDFAPP_OUTLINE_LOAD_NOW;
		winreloadpage(app);
	}
	else if (app->incomplete)
		winreloadpage(app);
}
#endif

static int make_fake_doc(pdfapp_t *app)
{
	fz_context *ctx = app->ctx;
	pdf_document *pdf = NULL;
	fz_buffer *contents = NULL;
	pdf_obj *page_obj = NULL;

	fz_var(contents);
	fz_var(page_obj);

	fz_try(ctx)
	{
		fz_rect mediabox = { 0, 0, app->winw, app->winh };
		int i;

		pdf = pdf_create_document(ctx);


		contents = fz_new_buffer(ctx, 100);
		fz_append_printf(ctx, contents, "1 0 0 RG %g w 0 0 m %g %g l 0 %g m %g 0 l s\n",
			fz_min(mediabox.x1, mediabox.y1) / 20,
			mediabox.x1, mediabox.y1,
			mediabox.y1, mediabox.x1);

		/* Create enough copies of our blank(ish) page so that the
		 * page number is preserved if and when a subsequent load
		 * works. */
		page_obj = pdf_add_page(ctx, pdf, &mediabox, 0, NULL, contents);
		for (i = 0; i < app->pagecount; i++)
			pdf_insert_page(ctx, pdf, -1, page_obj);
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, page_obj);
		fz_drop_buffer(ctx, contents);
	}
	fz_catch(ctx)
	{
		fz_drop_document(ctx, (fz_document *) pdf);
		return 1;
	}

	app->doc = (fz_document*)pdf;
	return 0;
}

void pdfapp_open_progressive(pdfapp_t *app, char *filename, int reload, int bps)
{
	fz_context *ctx = app->ctx;
	char *password = "";

	fz_try(ctx)
	{
		fz_register_document_handlers(ctx);

		if (app->layout_css)
		{
			fz_buffer *buf = fz_read_file(ctx, app->layout_css);
			fz_set_user_css(ctx, fz_string_from_buffer(ctx, buf));
			fz_drop_buffer(ctx, buf);
		}

		fz_set_use_document_css(ctx, app->layout_use_doc_css);

#ifdef HAVE_CURL
		if (!strncmp(filename, "http://", 7) || !strncmp(filename, "https://", 8))
		{
			app->stream = fz_stream_from_curl(ctx, filename, pdfapp_more_data, app);
			while (1)
			{
				fz_try(ctx)
				{
					fz_seek(ctx, app->stream, 0, SEEK_SET);
					app->doc = fz_open_document_with_stream(ctx, filename, app->stream);
				}
				fz_catch(ctx)
				{
					if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
					{
						pdfapp_warn(app, "not enough data to open yet");
						continue;
					}
					fz_rethrow(ctx);
				}
				break;
			}
		}
		else
#endif
		if (bps == 0)
		{
			app->doc = fz_open_document(ctx, filename);
		}
		else
		{
			fz_stream *stream = fz_open_file_progressive(ctx, filename, bps);
			while (1)
			{
				fz_try(ctx)
				{
					fz_seek(ctx, stream, 0, SEEK_SET);
					app->doc = fz_open_document_with_stream(ctx, filename, stream);
				}
				fz_catch(ctx)
				{
					if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
					{
						pdfapp_warn(app, "not enough data to open yet");
						continue;
					}
					fz_rethrow(ctx);
				}
				break;
			}
		}
	}
	fz_catch(ctx)
	{
		if (!reload || make_fake_doc(app))
			pdfapp_error(app, "cannot open document");
	}

	fz_try(ctx)
	{
		pdf_document *idoc;

		idoc = pdf_specifics(app->ctx, app->doc);

		if (idoc)
		{
			pdf_enable_js(ctx, idoc);
			pdf_set_doc_event_callback(ctx, idoc, event_cb, app);
		}

		if (fz_needs_password(app->ctx, app->doc))
		{
			int okay = fz_authenticate_password(app->ctx, app->doc, password);
			while (!okay)
			{
				password = winpassword(app, filename);
				if (!password)
					fz_throw(ctx, FZ_ERROR_GENERIC, "Needs a password");
				okay = fz_authenticate_password(app->ctx, app->doc, password);
				if (!okay)
					pdfapp_warn(app, "Invalid password.");
			}
		}

		app->docpath = fz_strdup(ctx, filename);
		app->doctitle = filename;
		if (strrchr(app->doctitle, '\\'))
			app->doctitle = strrchr(app->doctitle, '\\') + 1;
		if (strrchr(app->doctitle, '/'))
			app->doctitle = strrchr(app->doctitle, '/') + 1;
		app->doctitle = fz_strdup(ctx, app->doctitle);

		fz_layout_document(app->ctx, app->doc, app->layout_w, app->layout_h, app->layout_em);

		while (1)
		{
			fz_try(ctx)
			{
				app->pagecount = fz_count_pages(app->ctx, app->doc);
				if (app->pagecount <= 0)
					fz_throw(ctx, FZ_ERROR_GENERIC, "No pages in document");
			}
			fz_catch(ctx)
			{
				if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
				{
					pdfapp_warn(app, "not enough data to count pages yet");
					continue;
				}
				fz_rethrow(ctx);
			}
			break;
		}
		while (1)
		{
			fz_try(ctx)
			{
				app->outline = fz_load_outline(app->ctx, app->doc);
			}
			fz_catch(ctx)
			{
				app->outline = NULL;
				if (fz_caught(ctx) == FZ_ERROR_TRYLATER)
					app->outline_deferred = PDFAPP_OUTLINE_DEFERRED;
			}
			break;
		}
	}
	fz_catch(ctx)
	{
		pdfapp_error(app, "cannot open document");
	}

	if (app->pageno < 1)
		app->pageno = 1;
	if (app->pageno > app->pagecount)
		app->pageno = app->pagecount;
	if (app->resolution < MINRES)
		app->resolution = MINRES;
	if (app->resolution > MAXRES)
		app->resolution = MAXRES;

	if (!reload)
	{
		app->shrinkwrap = 1;
		app->rotate = 0;
		app->panx = 0;
		app->pany = 0;
	}

	pdfapp_showpage(app, 1, 1, 1, 0, 0);
}

void pdfapp_close(pdfapp_t *app)
{
	fz_drop_display_list(app->ctx, app->page_list);
	app->page_list = NULL;

	fz_drop_display_list(app->ctx, app->annotations_list);
	app->annotations_list = NULL;

	fz_drop_stext_page(app->ctx, app->page_text);
	app->page_text = NULL;

	fz_drop_stext_sheet(app->ctx, app->page_sheet);
	app->page_sheet = NULL;

	fz_drop_link(app->ctx, app->page_links);
	app->page_links = NULL;

	fz_free(app->ctx, app->doctitle);
	app->doctitle = NULL;

	fz_free(app->ctx, app->docpath);
	app->docpath = NULL;

	fz_drop_pixmap(app->ctx, app->image);
	app->image = NULL;

	fz_drop_pixmap(app->ctx, app->new_image);
	app->new_image = NULL;

	fz_drop_pixmap(app->ctx, app->old_image);
	app->old_image = NULL;

	fz_drop_outline(app->ctx, app->outline);
	app->outline = NULL;

	fz_drop_page(app->ctx, app->page);
	app->page = NULL;

	fz_drop_document(app->ctx, app->doc);
	app->doc = NULL;

#ifdef HAVE_CURL
	fz_drop_stream(app->ctx, app->stream);
#endif

	fz_flush_warnings(app->ctx);
}

static int gen_tmp_file(char *buf, int len)
{
	int i;
	char *name = strrchr(buf, '/');

	if (name == NULL)
		name = strrchr(buf, '\\');

	if (name != NULL)
		name++;
	else
		name = buf;

	for (i = 0; i < 10000; i++)
	{
		FILE *f;
		snprintf(name, buf+len-name, "tmp%04d", i);
		f = fopen(buf, "r");
		if (f == NULL)
			return 1;
		fclose(f);
	}

	return 0;
}

static int pdfapp_save(pdfapp_t *app)
{
	char buf[PATH_MAX];

	pdf_document *idoc = pdf_specifics(app->ctx, app->doc);
	if (!idoc)
		return 0;

	if (wingetsavepath(app, buf, PATH_MAX))
	{
		pdf_write_options opts = { 0 };

		opts.do_incremental = pdf_can_be_saved_incrementally(app->ctx, idoc);

		if (strcmp(buf, app->docpath) != 0)
		{
			wincopyfile(app->docpath, buf);
			pdf_save_document(app->ctx, idoc, buf, &opts);
			return 1;
		}

		if (gen_tmp_file(buf, PATH_MAX))
		{
			int written = 0;

			fz_try(app->ctx)
			{
				wincopyfile(app->docpath, buf);
				pdf_save_document(app->ctx, idoc, buf, &opts);
				written = 1;
			}
			fz_catch(app->ctx)
			{
			}

			if (written)
			{
				char buf2[PATH_MAX];
				fz_strlcpy(buf2, app->docpath, PATH_MAX);
				pdfapp_close(app);
				winreplacefile(buf, buf2);
				pdfapp_open(app, buf2, 1);

				return written;
			}
		}
	}

	return 0;
}

int pdfapp_preclose(pdfapp_t *app)
{
	pdf_document *idoc = pdf_specifics(app->ctx, app->doc);

	if (idoc && pdf_has_unsaved_changes(app->ctx, idoc))
	{
		switch (winsavequery(app))
		{
		case DISCARD:
			return 1;

		case CANCEL:
			return 0;

		case SAVE:
			return pdfapp_save(app);
		}
	}

	return 1;
}

static void pdfapp_viewctm(fz_matrix *mat, pdfapp_t *app)
{
	fz_pre_rotate(fz_scale(mat, app->resolution/72.0f, app->resolution/72.0f), app->rotate);
}

static void pdfapp_panview(pdfapp_t *app, int newx, int newy)
{
	int image_w = 0;
	int image_h = 0;

	if (app->image)
	{
		image_w = fz_pixmap_width(app->ctx, app->image);
		image_h = fz_pixmap_height(app->ctx, app->image);
	}

	if (newx > 0)
		newx = 0;
	if (newy > 0)
		newy = 0;

	if (newx + image_w < app->winw)
		newx = app->winw - image_w;
	if (newy + image_h < app->winh)
		newy = app->winh - image_h;

	if (app->winw >= image_w)
		newx = (app->winw - image_w) / 2;
	if (app->winh >= image_h)
		newy = (app->winh - image_h) / 2;

	if (newx != app->panx || newy != app->pany)
		winrepaint(app);

	app->panx = newx;
	app->pany = newy;
}

static void pdfapp_loadpage(pdfapp_t *app, int no_cache)
{
	fz_device *mdev = NULL;
	int errored = 0;
	fz_cookie cookie = { 0 };

	fz_var(mdev);

	fz_drop_display_list(app->ctx, app->page_list);
	fz_drop_display_list(app->ctx, app->annotations_list);
	fz_drop_stext_page(app->ctx, app->page_text);
	fz_drop_stext_sheet(app->ctx, app->page_sheet);
	fz_drop_link(app->ctx, app->page_links);
	fz_drop_page(app->ctx, app->page);

	app->page_list = NULL;
	app->annotations_list = NULL;
	app->page_text = NULL;
	app->page_sheet = NULL;
	app->page_links = NULL;
	app->page = NULL;
	app->page_bbox.x0 = 0;
	app->page_bbox.y0 = 0;
	app->page_bbox.x1 = 100;
	app->page_bbox.y1 = 100;

	app->incomplete = 0;

	fz_try(app->ctx)
	{
		app->page = fz_load_page(app->ctx, app->doc, app->pageno - 1);

		fz_bound_page(app->ctx, app->page, &app->page_bbox);
	}
	fz_catch(app->ctx)
	{
		if (fz_caught(app->ctx) == FZ_ERROR_TRYLATER)
			app->incomplete = 1;
		else
			pdfapp_warn(app, "Cannot load page");
		return;
	}

	fz_try(app->ctx)
	{
		fz_annot *annot;
		/* Create display lists */
		app->page_list = fz_new_display_list(app->ctx, NULL);
		mdev = fz_new_list_device(app->ctx, app->page_list);
		if (no_cache)
			fz_enable_device_hints(app->ctx, mdev, FZ_NO_CACHE);
		cookie.incomplete_ok = 1;
		fz_run_page_contents(app->ctx, app->page, mdev, &fz_identity, &cookie);
		fz_close_device(app->ctx, mdev);
		fz_drop_device(app->ctx, mdev);
		mdev = NULL;
		app->annotations_list = fz_new_display_list(app->ctx, NULL);
		mdev = fz_new_list_device(app->ctx, app->annotations_list);
		for (annot = fz_first_annot(app->ctx, app->page); annot; annot = fz_next_annot(app->ctx, annot))
			fz_run_annot(app->ctx, annot, mdev, &fz_identity, &cookie);
		if (cookie.incomplete)
		{
			app->incomplete = 1;
			//pdfapp_warn(app, "Incomplete page rendering");
		}
		else if (cookie.errors)
		{
			pdfapp_warn(app, "Errors found on page");
			errored = 1;
		}
		fz_close_device(app->ctx, mdev);
	}
	fz_always(app->ctx)
	{
		fz_drop_device(app->ctx, mdev);
	}
	fz_catch(app->ctx)
	{
		if (fz_caught(app->ctx) == FZ_ERROR_TRYLATER)
			app->incomplete = 1;
		else
		{
			pdfapp_warn(app, "Cannot load page");
			errored = 1;
		}
	}

	fz_try(app->ctx)
	{
		app->page_links = fz_load_links(app->ctx, app->page);
	}
	fz_catch(app->ctx)
	{
		if (fz_caught(app->ctx) == FZ_ERROR_TRYLATER)
			app->incomplete = 1;
		else if (!errored)
			pdfapp_warn(app, "Cannot load page");
	}

	app->errored = errored;
}

static void pdfapp_recreate_annotationslist(pdfapp_t *app)
{
	fz_device *mdev = NULL;
	int errored = 0;
	fz_cookie cookie = { 0 };

	fz_var(mdev);

	fz_drop_display_list(app->ctx, app->annotations_list);
	app->annotations_list = NULL;

	fz_try(app->ctx)
	{
		fz_annot *annot;
		/* Create display list */
		app->annotations_list = fz_new_display_list(app->ctx, NULL);
		mdev = fz_new_list_device(app->ctx, app->annotations_list);
		for (annot = fz_first_annot(app->ctx, app->page); annot; annot = fz_next_annot(app->ctx, annot))
			fz_run_annot(app->ctx, annot, mdev, &fz_identity, &cookie);
		if (cookie.incomplete)
		{
			app->incomplete = 1;
			//pdfapp_warn(app, "Incomplete page rendering");
		}
		else if (cookie.errors)
		{
			pdfapp_warn(app, "Errors found on page");
			errored = 1;
		}
		fz_close_device(app->ctx, mdev);
	}
	fz_always(app->ctx)
	{
		fz_drop_device(app->ctx, mdev);
	}
	fz_catch(app->ctx)
	{
		pdfapp_warn(app, "Cannot load page");
		errored = 1;
	}

	app->errored = errored;
}

static void pdfapp_runpage(pdfapp_t *app, fz_device *dev, const fz_matrix *ctm, const fz_rect *rect, fz_cookie *cookie)
{
	if (app->page_list)
		fz_run_display_list(app->ctx, app->page_list, dev, ctm, rect, cookie);
	if (app->annotations_list)
		fz_run_display_list(app->ctx, app->annotations_list, dev, ctm, rect, cookie);
}

#define MAX_TITLE 256

static void pdfapp_updatepage(pdfapp_t *app)
{
	fz_device *idev;
	fz_matrix ctm;
	pdf_annot *pannot;

	pdfapp_viewctm(&ctm, app);
	pdf_update_page(app->ctx, (pdf_page *)app->page);
	pdfapp_recreate_annotationslist(app);

	for (pannot = pdf_first_annot(app->ctx, (pdf_page*)app->page); pannot; pannot = pdf_next_annot(app->ctx, pannot))
	{
		if (pannot->changed)
		{
			fz_annot *annot = (fz_annot*)pannot;
			fz_rect bounds;
			fz_irect ibounds;
			fz_transform_rect(fz_bound_annot(app->ctx, annot, &bounds), &ctm);
			fz_rect_from_irect(&bounds, fz_round_rect(&ibounds, &bounds));
			fz_clear_pixmap_rect_with_value(app->ctx, app->image, 255, &ibounds);
			idev = fz_new_draw_device_with_bbox(app->ctx, NULL, app->image, &ibounds);
			pdfapp_runpage(app, idev, &ctm, &bounds, NULL);
			fz_close_device(app->ctx, idev);
			fz_drop_device(app->ctx, idev);
		}
	}

	pdfapp_showpage(app, 0, 0, 1, 0, 0);
}

void pdfapp_reloadpage(pdfapp_t *app)
{
	if (app->outline_deferred == PDFAPP_OUTLINE_LOAD_NOW)
	{
		fz_try(app->ctx)
			app->outline = fz_load_outline(app->ctx, app->doc);
		fz_catch(app->ctx)
			app->outline = NULL;
		app->outline_deferred = 0;
	}
	pdfapp_showpage(app, 1, 1, 1, 0, 0);
}

static void pdfapp_showpage(pdfapp_t *app, int loadpage, int drawpage, int repaint, int transition, int searching)
{
	char buf[MAX_TITLE];
	fz_device *idev;
	fz_device *tdev;
	fz_colorspace *colorspace;
	fz_matrix ctm;
	fz_rect bounds;
	fz_irect ibounds;
	fz_cookie cookie = { 0 };

	if (!app->nowaitcursor)
		wincursor(app, WAIT);

	if (!app->transitions_enabled || !app->presentation_mode)
		transition = 0;

	if (transition)
	{
		app->old_image = app->image;
		app->image = NULL;
	}

	if (loadpage)
	{
		fz_rect mediabox;
		pdfapp_loadpage(app, searching);

		/* Zero search hit position */
		app->hit_count = 0;

		/* Extract text */
		app->page_sheet = fz_new_stext_sheet(app->ctx);
		app->page_text = fz_new_stext_page(app->ctx, fz_bound_page(app->ctx, app->page, &mediabox));

		if (app->page_list || app->annotations_list)
		{
			tdev = fz_new_stext_device(app->ctx, app->page_sheet, app->page_text, NULL);
			pdfapp_runpage(app, tdev, &fz_identity, &fz_infinite_rect, &cookie);
			fz_close_device(app->ctx, tdev);
			fz_drop_device(app->ctx, tdev);
		}
	}

	if (drawpage)
	{
		char buf2[64];
		size_t len;

		sprintf(buf2, " - %d/%d (%d dpi)",
				app->pageno, app->pagecount, app->resolution);
		len = MAX_TITLE-strlen(buf2);
		if (strlen(app->doctitle) > len)
		{
			snprintf(buf, len-3, "%s", app->doctitle);
			strcat(buf, "...");
			strcat(buf, buf2);
		}
		else
			sprintf(buf, "%s%s", app->doctitle, buf2);
		wintitle(app, buf);

		pdfapp_viewctm(&ctm, app);
		bounds = app->page_bbox;
		fz_round_rect(&ibounds, fz_transform_rect(&bounds, &ctm));
		fz_rect_from_irect(&bounds, &ibounds);

		/* Draw */
		fz_drop_pixmap(app->ctx, app->image);
		if (app->grayscale)
			colorspace = fz_device_gray(app->ctx);
		else
			colorspace = app->colorspace;

		app->image = NULL;
		fz_var(app->image);

		fz_try(app->ctx)
		{
			app->image = fz_new_pixmap_with_bbox(app->ctx, colorspace, &ibounds, 1);
			fz_clear_pixmap_with_value(app->ctx, app->image, 255);
			if (app->page_list || app->annotations_list)
			{
				idev = fz_new_draw_device(app->ctx, NULL, app->image);
				pdfapp_runpage(app, idev, &ctm, &bounds, &cookie);
				fz_close_device(app->ctx, idev);
				fz_drop_device(app->ctx, idev);
			}
			if (app->invert)
				fz_invert_pixmap(app->ctx, app->image);
			if (app->tint)
				fz_tint_pixmap(app->ctx, app->image, app->tint_r, app->tint_g, app->tint_b);
		}
		fz_catch(app->ctx)
		{
			cookie.errors++;
		}
	}

	if (transition)
	{
		app->new_image = app->image;
		app->image = NULL;
		if (app->grayscale)
			colorspace = fz_device_gray(app->ctx);
		else
			colorspace = app->colorspace;
		app->image = fz_new_pixmap_with_bbox(app->ctx, colorspace, &ibounds, 1);
		app->duration = 0;
		fz_page_presentation(app->ctx, app->page, &app->transition, &app->duration);
		if (app->duration == 0)
			app->duration = 5;
		app->in_transit = fz_generate_transition(app->ctx, app->image, app->old_image, app->new_image, 0, &app->transition);
		if (!app->in_transit)
		{
			if (app->duration != 0)
				winadvancetimer(app, app->duration);
		}
		app->start_time = clock();
	}

	if (repaint)
	{
		pdfapp_panview(app, app->panx, app->pany);

		if (!app->image)
		{
			/* there is no image to blit, but there might be an error message */
			winresize(app, app->layout_w, app->layout_h);
		}
		else if (app->shrinkwrap)
		{
			int w = fz_pixmap_width(app->ctx, app->image);
			int h = fz_pixmap_height(app->ctx, app->image);

			if (app->winw == w)
				app->panx = 0;
			if (app->winh == h)
				app->pany = 0;
			if (w > app->scrw * 90 / 100)
				w = app->scrw * 90 / 100;
			if (h > app->scrh * 90 / 100)
				h = app->scrh * 90 / 100;
			if (w != app->winw || h != app->winh)
				winresize(app, w, h);
		}

		winrepaint(app);

		wincursor(app, ARROW);
	}

	if (cookie.errors && app->errored == 0)
	{
		app->errored = 1;
		pdfapp_warn(app, "Errors found on page. Page rendering may be incomplete.");
	}

	fz_flush_warnings(app->ctx);
}

static void pdfapp_gotouri(pdfapp_t *app, char *uri)
{
	winopenuri(app, uri);
}

void pdfapp_gotopage(pdfapp_t *app, int number)
{
	app->issearching = 0;
	winrepaint(app);

	if (number < 1)
		number = 1;
	if (number > app->pagecount)
		number = app->pagecount;

	if (number == app->pageno)
		return;

	if (app->histlen + 1 == 256)
	{
		memmove(app->hist, app->hist + 1, sizeof(int) * 255);
		app->histlen --;
	}
	app->hist[app->histlen++] = app->pageno;
	app->pageno = number;
	pdfapp_showpage(app, 1, 1, 1, 0, 0);
}

void pdfapp_inverthit(pdfapp_t *app)
{
	fz_rect bbox;
	fz_matrix ctm;
	int i;

	pdfapp_viewctm(&ctm, app);

	for (i = 0; i < app->hit_count; i++)
	{
		bbox = app->hit_bbox[i];
		pdfapp_invert(app, fz_transform_rect(&bbox, &ctm));
	}
}

static void pdfapp_search_in_direction(pdfapp_t *app, enum panning *panto, int dir)
{
	int firstpage, page;

	/* abort if no search string */
	if (app->search[0] == 0)
	{
		winrepaint(app);
		return;
	}

	wincursor(app, WAIT);

	firstpage = app->pageno;
	if (app->searchpage == app->pageno)
		page = app->pageno + dir;
	else
		page = app->pageno;

	if (page < 1) page = app->pagecount;
	if (page > app->pagecount) page = 1;

	do
	{
		if (page != app->pageno)
		{
			app->pageno = page;
			pdfapp_showpage(app, 1, 0, 0, 0, 1);
		}

		app->hit_count = fz_search_stext_page(app->ctx, app->page_text, app->search, app->hit_bbox, nelem(app->hit_bbox));
		if (app->hit_count > 0)
		{
			*panto = dir == 1 ? PAN_TO_TOP : PAN_TO_BOTTOM;
			app->searchpage = app->pageno;
			wincursor(app, HAND);
			winrepaint(app);
			return;
		}

		page += dir;
		if (page < 1) page = app->pagecount;
		if (page > app->pagecount) page = 1;
	} while (page != firstpage);

	pdfapp_warn(app, "String '%s' not found.", app->search);

	app->pageno = firstpage;
	pdfapp_showpage(app, 1, 0, 0, 0, 0);
	wincursor(app, HAND);
	winrepaint(app);
}

void pdfapp_onresize(pdfapp_t *app, int w, int h)
{
	if (app->winw != w || app->winh != h)
	{
		app->winw = w;
		app->winh = h;
		pdfapp_panview(app, app->panx, app->pany);
		winrepaint(app);
	}
}

void pdfapp_autozoom_vertical(pdfapp_t *app)
{
	app->resolution *= (double) app->winh / (double) fz_pixmap_height(app->ctx, app->image);
	if (app->resolution > MAXRES)
		app->resolution = MAXRES;
	else if (app->resolution < MINRES)
		app->resolution = MINRES;
	pdfapp_showpage(app, 0, 1, 1, 0, 0);
}

void pdfapp_autozoom_horizontal(pdfapp_t *app)
{
	app->resolution *= (double) app->winw / (double) fz_pixmap_width(app->ctx, app->image);
	if (app->resolution > MAXRES)
		app->resolution = MAXRES;
	else if (app->resolution < MINRES)
		app->resolution = MINRES;
	pdfapp_showpage(app, 0, 1, 1, 0, 0);
}

void pdfapp_autozoom(pdfapp_t *app)
{
	float page_aspect = (float) fz_pixmap_width(app->ctx, app->image) / fz_pixmap_height(app->ctx, app->image);
	float win_aspect = (float) app->winw / app->winh;
	if (page_aspect > win_aspect)
		pdfapp_autozoom_horizontal(app);
	else
		pdfapp_autozoom_vertical(app);
}

void pdfapp_onkey(pdfapp_t *app, int c, int modifiers)
{
	int oldpage = app->pageno;
	enum panning panto = PAN_TO_TOP;
	int loadpage = 1;

	if (app->issearching)
	{
		size_t n = strlen(app->search);
		if (c < ' ')
		{
			if (c == '\b' && n > 0)
			{
				app->search[n - 1] = 0;
				winrepaintsearch(app);
			}
			if (c == '\n' || c == '\r')
			{
				app->issearching = 0;
				if (n > 0)
				{
					winrepaintsearch(app);

					if (app->searchdir < 0)
					{
						if (app->pageno == 1)
							app->pageno = app->pagecount;
						else
							app->pageno--;
						pdfapp_showpage(app, 1, 1, 0, 0, 1);
					}

					pdfapp_onkey(app, 'n', 0);
				}
				else
					winrepaint(app);
			}
			if (c == '\033')
			{
				app->issearching = 0;
				winrepaint(app);
			}
		}
		else
		{
			if (n + 2 < sizeof app->search)
			{
				app->search[n] = c;
				app->search[n + 1] = 0;
				winrepaintsearch(app);
			}
		}
		return;
	}

	/*
	 * Save numbers typed for later
	 */

	if (c >= '0' && c <= '9')
	{
		app->number[app->numberlen++] = c;
		app->number[app->numberlen] = '\0';
	}

	switch (c)
	{
	case 'q':
		winclose(app);
		break;

	case '[':
		if (app->layout_em > 8)
		{
			float percent = (float)app->pageno / app->pagecount;
			app->layout_em -= 2;
			fz_layout_document(app->ctx, app->doc, app->layout_w, app->layout_h, app->layout_em);
			app->pagecount = fz_count_pages(app->ctx, app->doc);
			app->pageno = app->pagecount * percent + 0.1;
			pdfapp_showpage(app, 1, 1, 1, 0, 0);
		}
		break;
	case ']':
		if (app->layout_em < 36)
		{
			float percent = (float)app->pageno / app->pagecount;
			app->layout_em += 2;
			fz_layout_document(app->ctx, app->doc, app->layout_w, app->layout_h, app->layout_em);
			app->pagecount = fz_count_pages(app->ctx, app->doc);
			app->pageno = app->pagecount * percent + 0.1;
			pdfapp_showpage(app, 1, 1, 1, 0, 0);
		}
		break;

	/*
	 * Zoom and rotate
	 */

	case '+':
	case '=':
		app->resolution = zoom_in(app->resolution);
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;
	case '-':
		app->resolution = zoom_out(app->resolution);
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;

	case 'W':
		pdfapp_autozoom_horizontal(app);
		break;
	case 'H':
		pdfapp_autozoom_vertical(app);
		break;
	case 'Z':
		pdfapp_autozoom(app);
		break;

	case 'L':
		app->rotate -= 90;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;
	case 'R':
		app->rotate += 90;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;

	case 'C':
		app->tint ^= 1;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;

	case 'c':
		app->grayscale ^= 1;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;

	case 'i':
		app->invert ^= 1;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;

#ifndef NDEBUG
	case 'a':
		app->rotate -= 15;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;
	case 's':
		app->rotate += 15;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
		break;
#endif

	/*
	 * Pan view, but don't need to repaint image
	 */

	case 'f':
		app->shrinkwrap = 0;
		winfullscreen(app, !app->fullscreen);
		app->fullscreen = !app->fullscreen;
		break;

	case 'w':
		if (app->fullscreen)
		{
			winfullscreen(app, 0);
			app->fullscreen = 0;
		}
		app->shrinkwrap = 1;
		app->panx = app->pany = 0;
		pdfapp_showpage(app, 0, 0, 1, 0, 0);
		break;

	case 'h':
		app->panx += fz_pixmap_width(app->ctx, app->image) / 10;
		pdfapp_showpage(app, 0, 0, 1, 0, 0);
		break;

	case 'j':
		{
			int h = fz_pixmap_height(app->ctx, app->image);
			if (h <= app->winh || app->pany <= app->winh - h)
			{
				panto = PAN_TO_TOP;
				app->pageno++;
			}
			else
			{
				app->pany -= h / 10;
				pdfapp_showpage(app, 0, 0, 1, 0, 0);
			}
			break;
		}

	case 'k':
		{
			int h = fz_pixmap_height(app->ctx, app->image);
			if (h <= app->winh || app->pany == 0)
			{
				panto = PAN_TO_BOTTOM;
				app->pageno--;
			}
			else
			{
				app->pany += h / 10;
				pdfapp_showpage(app, 0, 0, 1, 0, 0);
			}
			break;
		}

	case 'l':
		app->panx -= fz_pixmap_width(app->ctx, app->image) / 10;
		pdfapp_showpage(app, 0, 0, 1, 0, 0);
		break;

	/*
	 * Page navigation
	 */

	case 'g':
	case '\n':
	case '\r':
		if (app->numberlen > 0)
			pdfapp_gotopage(app, atoi(app->number));
		else
			pdfapp_gotopage(app, 1);
		break;

	case 'G':
		pdfapp_gotopage(app, app->pagecount);
		break;

	case 'm':
		if (app->numberlen > 0)
		{
			int idx = atoi(app->number);
			if (idx >= 0 && idx < nelem(app->marks))
				app->marks[idx] = app->pageno;
		}
		else
		{
			if (app->histlen + 1 == 256)
			{
				memmove(app->hist, app->hist + 1, sizeof(int) * 255);
				app->histlen --;
			}
			app->hist[app->histlen++] = app->pageno;
		}
		break;

	case 't':
		if (app->numberlen > 0)
		{
			int idx = atoi(app->number);

			if (idx >= 0 && idx < nelem(app->marks))
				if (app->marks[idx] > 0)
					app->pageno = app->marks[idx];
		}
		else if (app->histlen > 0)
			app->pageno = app->hist[--app->histlen];
		break;

	case 'p':
		app->presentation_mode = !app->presentation_mode;
		break;

	/*
	 * Back and forth ...
	 */

	case ',':
		panto = PAN_TO_BOTTOM;
		if (app->numberlen > 0)
			app->pageno -= atoi(app->number);
		else
			app->pageno--;
		break;

	case '.':
		panto = PAN_TO_TOP;
		if (app->numberlen > 0)
			app->pageno += atoi(app->number);
		else
			app->pageno++;
		break;

	case '\b':
	case 'b':
		panto = DONT_PAN;
		if (app->numberlen > 0)
			app->pageno -= atoi(app->number);
		else
			app->pageno--;
		break;

	case ' ':
		panto = DONT_PAN;
		if (modifiers & 1)
		{
			if (app->numberlen > 0)
				app->pageno -= atoi(app->number);
			else
				app->pageno--;
		}
		else
		{
			if (app->numberlen > 0)
				app->pageno += atoi(app->number);
			else
				app->pageno++;
		}
		break;

	case '<':
		panto = PAN_TO_TOP;
		app->pageno -= 10;
		break;
	case '>':
		panto = PAN_TO_TOP;
		app->pageno += 10;
		break;

	/*
	 * Saving the file
	 */
	case 'S':
		pdfapp_save(app);
		break;

	/*
	 * Reloading the file...
	 */

	case 'r':
		panto = DONT_PAN;
		oldpage = -1;
		pdfapp_reloadfile(app);
		break;

	/*
	 * Searching
	 */

	case '?':
		app->issearching = 1;
		app->searchdir = -1;
		app->search[0] = 0;
		app->hit_count = 0;
		app->searchpage = -1;
		winrepaintsearch(app);
		break;

	case '/':
		app->issearching = 1;
		app->searchdir = 1;
		app->search[0] = 0;
		app->hit_count = 0;
		app->searchpage = -1;
		winrepaintsearch(app);
		break;

	case 'n':
		if (app->searchdir > 0)
			pdfapp_search_in_direction(app, &panto, 1);
		else
			pdfapp_search_in_direction(app, &panto, -1);
		loadpage = 0;
		break;

	case 'N':
		if (app->searchdir > 0)
			pdfapp_search_in_direction(app, &panto, -1);
		else
			pdfapp_search_in_direction(app, &panto, 1);
		loadpage = 0;
		break;
	}

	if (c < '0' || c > '9')
		app->numberlen = 0;

	if (app->pageno < 1)
		app->pageno = 1;
	if (app->pageno > app->pagecount)
		app->pageno = app->pagecount;

	if (app->pageno != oldpage)
	{
		switch (panto)
		{
		case PAN_TO_TOP:
			app->pany = 0;
			break;
		case PAN_TO_BOTTOM:
			app->pany = -2000;
			break;
		case DONT_PAN:
			break;
		}
		pdfapp_showpage(app, loadpage, 1, 1, 1, 0);
	}
}

static void handlescroll(pdfapp_t *app, int modifiers, int dir)
{
	app->ispanning = app->iscopying = 0;
	if (modifiers & (1<<2))
	{
		/* zoom in/out if ctrl is pressed */
		if (dir < 0)
			app->resolution = zoom_in(app->resolution);
		else
			app->resolution = zoom_out(app->resolution);
		if (app->resolution > MAXRES)
			app->resolution = MAXRES;
		if (app->resolution < MINRES)
			app->resolution = MINRES;
		pdfapp_showpage(app, 0, 1, 1, 0, 0);
	}
	else
	{
		/* scroll up/down, or left/right if
		shift is pressed */
		int w = fz_pixmap_width(app->ctx, app->image);
		int h = fz_pixmap_height(app->ctx, app->image);
		int xstep = 0;
		int ystep = 0;
		int pagestep = 0;
		if (modifiers & (1<<0))
		{
			if (dir > 0 && app->panx >= 0)
				pagestep = -1;
			else if (dir < 0 && app->panx <= app->winw - w)
				pagestep = 1;
			else
				xstep = 20 * dir;
		}
		else
		{
			if (dir > 0 && app->pany >= 0)
				pagestep = -1;
			else if (dir < 0 && app->pany <= app->winh - h)
				pagestep = 1;
			else
				ystep = 20 * dir;
		}
		if (pagestep == 0)
			pdfapp_panview(app, app->panx + xstep, app->pany + ystep);
		else if (pagestep > 0 && app->pageno < app->pagecount)
		{
			app->pageno++;
			app->pany = 0;
			pdfapp_showpage(app, 1, 1, 1, 0, 0);
		}
		else if (pagestep < 0 && app->pageno > 1)
		{
			app->pageno--;
			app->pany = INT_MIN;
			pdfapp_showpage(app, 1, 1, 1, 0, 0);
		}
	}
}

void pdfapp_onmouse(pdfapp_t *app, int x, int y, int btn, int modifiers, int state)
{
	fz_context *ctx = app->ctx;
	fz_irect irect = { 0, 0, app->layout_w, app->layout_h };
	fz_link *link;
	fz_matrix ctm;
	fz_point p;
	int processed = 0;

	if (app->image)
		fz_pixmap_bbox(app->ctx, app->image, &irect);
	p.x = x - app->panx + irect.x0;
	p.y = y - app->pany + irect.y0;

	pdfapp_viewctm(&ctm, app);
	fz_invert_matrix(&ctm, &ctm);

	fz_transform_point(&p, &ctm);

	if (btn == 1 && (state == 1 || state == -1))
	{
		pdf_ui_event event;
		pdf_document *idoc = pdf_specifics(app->ctx, app->doc);

		event.etype = PDF_EVENT_TYPE_POINTER;
		event.event.pointer.pt = p;
		if (state == 1)
			event.event.pointer.ptype = PDF_POINTER_DOWN;
		else /* state == -1 */
			event.event.pointer.ptype = PDF_POINTER_UP;

		if (idoc && pdf_pass_event(ctx, idoc, (pdf_page *)app->page, &event))
		{
			pdf_widget *widget;

			widget = pdf_focused_widget(ctx, idoc);

			app->nowaitcursor = 1;
			pdfapp_updatepage(app);

			if (widget)
			{
				switch (pdf_widget_type(ctx, widget))
				{
				case PDF_WIDGET_TYPE_TEXT:
					{
						char *text = pdf_text_widget_text(ctx, idoc, widget);
						char *current_text = text;
						int retry = 0;

						do
						{
							current_text = wintextinput(app, current_text, retry);
							retry = 1;
						}
						while (current_text && !pdf_text_widget_set_text(ctx, idoc, widget, current_text));

						fz_free(app->ctx, text);
						pdfapp_updatepage(app);
					}
					break;
				case PDF_WIDGET_TYPE_LISTBOX:
				case PDF_WIDGET_TYPE_COMBOBOX:
					{
						int nopts;
						int nvals;
						char **opts = NULL;
						char **vals = NULL;

						fz_var(opts);
						fz_var(vals);

						fz_try(ctx)
						{
							nopts = pdf_choice_widget_options(ctx, idoc, widget, 0, NULL);
							opts = fz_malloc(ctx, nopts * sizeof(*opts));
							(void)pdf_choice_widget_options(ctx, idoc, widget, 0, opts);

							nvals = pdf_choice_widget_value(ctx, idoc, widget, NULL);
							vals = fz_malloc(ctx, MAX(nvals,nopts) * sizeof(*vals));
							(void)pdf_choice_widget_value(ctx, idoc, widget, vals);

							if (winchoiceinput(app, nopts, opts, &nvals, vals))
							{
								pdf_choice_widget_set_value(ctx, idoc, widget, nvals, vals);
								pdfapp_updatepage(app);
							}
						}
						fz_always(ctx)
						{
							fz_free(ctx, opts);
							fz_free(ctx, vals);
						}
						fz_catch(ctx)
						{
							pdfapp_warn(app, "setting of choice failed");
						}
					}
					break;

				case PDF_WIDGET_TYPE_SIGNATURE:
					if (state == -1)
					{
						char ebuf[256];

						ebuf[0] = 0;
						if (pdf_check_signature(ctx, idoc, widget, app->docpath, ebuf, sizeof(ebuf)))
						{
							winwarn(app, "Signature is valid");
						}
						else
						{
							if (ebuf[0] == 0)
								winwarn(app, "Signature check failed for unknown reason");
							else
								winwarn(app, ebuf);
						}
					}
					break;
				}
			}

			app->nowaitcursor = 0;
			processed = 1;
		}
	}

	for (link = app->page_links; link; link = link->next)
	{
		if (p.x >= link->rect.x0 && p.x <= link->rect.x1)
			if (p.y >= link->rect.y0 && p.y <= link->rect.y1)
				break;
	}

	if (link)
	{
		wincursor(app, HAND);
		if (btn == 1 && state == 1 && !processed)
		{
			if (fz_is_external_link(ctx, link->uri))
				pdfapp_gotouri(app, link->uri);
			else
				pdfapp_gotopage(app, fz_resolve_link(ctx, app->doc, link->uri, NULL, NULL) + 1);
			return;
		}
	}
	else
	{
		fz_annot *annot;
		for (annot = fz_first_annot(app->ctx, app->page); annot; annot = fz_next_annot(app->ctx, annot))
		{
			fz_rect rect;
			fz_bound_annot(app->ctx, annot, &rect);
			if (x >= rect.x0 && x < rect.x1)
				if (y >= rect.y0 && y < rect.y1)
					break;
		}
		if (annot)
			wincursor(app, CARET);
		else
			wincursor(app, ARROW);
	}

	if (state == 1 && !processed)
	{
		if (btn == 1 && !app->iscopying)
		{
			app->ispanning = 1;
			app->selx = x;
			app->sely = y;
			app->beyondy = 0;
		}
		if (btn == 3 && !app->ispanning)
		{
			app->iscopying = 1;
			app->selx = x;
			app->sely = y;
			app->selr.x0 = x;
			app->selr.x1 = x;
			app->selr.y0 = y;
			app->selr.y1 = y;
		}
		if (btn == 4 || btn == 5) /* scroll wheel */
		{
			handlescroll(app, modifiers, btn == 4 ? 1 : -1);
		}
		if (btn == 6 || btn == 7) /* scroll wheel (horizontal) */
		{
			/* scroll left/right or up/down if shift is pressed */
			handlescroll(app, modifiers ^ (1<<0), btn == 6 ? 1 : -1);
		}
		if (app->presentation_mode)
		{
			if (btn == 1 && app->pageno < app->pagecount)
			{
				app->pageno++;
				pdfapp_showpage(app, 1, 1, 1, 0, 0);
			}
			if (btn == 3 && app->pageno > 1)
			{
				app->pageno--;
				pdfapp_showpage(app, 1, 1, 1, 0, 0);
			}
		}
	}

	else if (state == -1)
	{
		if (app->iscopying)
		{
			app->iscopying = 0;
			app->selr.x0 = fz_mini(app->selx, x) - app->panx + irect.x0;
			app->selr.x1 = fz_maxi(app->selx, x) - app->panx + irect.x0;
			app->selr.y0 = fz_mini(app->sely, y) - app->pany + irect.y0;
			app->selr.y1 = fz_maxi(app->sely, y) - app->pany + irect.y0;
			winrepaint(app);
			if (app->selr.x0 < app->selr.x1 && app->selr.y0 < app->selr.y1)
				windocopy(app);
		}
		app->ispanning = 0;
	}

	else if (app->ispanning)
	{
		int newx = app->panx + x - app->selx;
		int newy = app->pany + y - app->sely;
		int imgh = app->winh;
		if (app->image)
			imgh = fz_pixmap_height(app->ctx, app->image);

		/* Scrolling beyond limits implies flipping pages */
		/* Are we requested to scroll beyond limits? */
		if (newy + imgh < app->winh || newy > 0)
		{
			/* Yes. We can assume that deltay != 0 */
			int deltay = y - app->sely;
			/* Check whether the panning has occurred in the
			 * direction that we are already crossing the
			 * limit it. If not, we can conclude that we
			 * have switched ends of the page and will thus
			 * start over counting.
			 */
			if( app->beyondy == 0 || (app->beyondy ^ deltay) >= 0 )
			{
				/* Updating how far we are beyond and
				 * flipping pages if beyond threshold
				 */
				app->beyondy += deltay;
				if (app->beyondy > BEYOND_THRESHHOLD)
				{
					if( app->pageno > 1 )
					{
						app->pageno--;
						pdfapp_showpage(app, 1, 1, 1, 0, 0);
						if (app->image)
							newy = -fz_pixmap_height(app->ctx, app->image);
					}
					app->beyondy = 0;
				}
				else if (app->beyondy < -BEYOND_THRESHHOLD)
				{
					if( app->pageno < app->pagecount )
					{
						app->pageno++;
						pdfapp_showpage(app, 1, 1, 1, 0, 0);
						newy = 0;
					}
					app->beyondy = 0;
				}
			}
			else
				app->beyondy = 0;
		}
		/* Although at this point we've already determined that
		 * or that no scrolling will be performed in
		 * y-direction, the x-direction has not yet been taken
		 * care off. Therefore
		 */
		pdfapp_panview(app, newx, newy);

		app->selx = x;
		app->sely = y;
	}

	else if (app->iscopying)
	{
		app->selr.x0 = fz_mini(app->selx, x) - app->panx + irect.x0;
		app->selr.x1 = fz_maxi(app->selx, x) - app->panx + irect.x0;
		app->selr.y0 = fz_mini(app->sely, y) - app->pany + irect.y0;
		app->selr.y1 = fz_maxi(app->sely, y) - app->pany + irect.y0;
		winrepaint(app);
	}
}

void pdfapp_oncopy(pdfapp_t *app, unsigned short *ucsbuf, int ucslen)
{
	fz_rect hitbox;
	fz_matrix ctm;
	fz_stext_page *page = app->page_text;
	int c, i, p, need_newline;
	int block_num;

	int x0 = app->selr.x0;
	int x1 = app->selr.x1;
	int y0 = app->selr.y0;
	int y1 = app->selr.y1;

	pdfapp_viewctm(&ctm, app);

	p = 0;
	need_newline = 0;

	for (block_num = 0; block_num < page->len; block_num++)
	{
		fz_stext_line *line;
		fz_stext_block *block;
		fz_stext_span *span;

		if (page->blocks[block_num].type != FZ_PAGE_BLOCK_TEXT)
			continue;
		block = page->blocks[block_num].u.text;

		for (line = block->lines; line < block->lines + block->len; line++)
		{
			int saw_text = 0;

			for (span = line->first_span; span; span = span->next)
			{
				for (i = 0; i < span->len; i++)
				{
					fz_stext_char_bbox(app->ctx, &hitbox, span, i);
					fz_transform_rect(&hitbox, &ctm);
					c = span->text[i].c;
					if (c < 32)
						c = '?';
					if (hitbox.x1 >= x0 && hitbox.x0 <= x1 && hitbox.y1 >= y0 && hitbox.y0 <= y1)
					{
						saw_text = 1;

						if (need_newline)
						{
#if defined(_WIN32) || defined(_WIN64)
							if (p < ucslen - 1)
								ucsbuf[p++] = '\r';
#endif
							if (p < ucslen - 1)
								ucsbuf[p++] = '\n';
							need_newline = 0;
						}

						if (p < ucslen - 1)
							ucsbuf[p++] = c;
					}
				}
			}

			if (saw_text)
				need_newline = 1;
		}
	}

	ucsbuf[p] = 0;
}

void pdfapp_postblit(pdfapp_t *app)
{
	clock_t time;
	float seconds;
	int llama;

	app->transitions_enabled = 1;
	if (!app->in_transit)
		return;
	time = clock();
	seconds = (float)(time - app->start_time) / CLOCKS_PER_SEC;
	llama = seconds * 256 / app->transition.duration;
	if (llama >= 256)
	{
		/* Completed. */
		fz_drop_pixmap(app->ctx, app->image);
		app->image = app->new_image;
		app->new_image = NULL;
		fz_drop_pixmap(app->ctx, app->old_image);
		app->old_image = NULL;
		if (app->duration != 0)
			winadvancetimer(app, app->duration);
	}
	else
		fz_generate_transition(app->ctx, app->image, app->old_image, app->new_image, llama, &app->transition);
	winrepaint(app);
	if (llama >= 256)
	{
		/* Completed. */
		app->in_transit = 0;
	}
}
