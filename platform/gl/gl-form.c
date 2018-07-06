#include "gl-app.h"

#include <string.h>
#include <stdio.h>

#ifndef PATH_MAX
#define PATH_MAX 2048
#endif

#include "mupdf/helpers/pkcs7-check.h"
#include "mupdf/helpers/pkcs7-openssl.h"

static char cert_filename[PATH_MAX];
static struct input cert_password;

static void do_sign(void)
{
#ifdef HAVE_LIBCRYPTO
	pdf_pkcs7_signer *signer = NULL;

	fz_var(signer);

	fz_try(ctx)
	{
		signer = pkcs7_openssl_read_pfx(ctx, cert_filename, cert_password.text);
		pdf_sign_signature(ctx, pdf, selected_annot, signer);
		ui_show_warning_dialog("Signed document successfully.");
	}
	fz_always(ctx)
	{
		if (signer)
			signer->drop(signer);
	}
	fz_catch(ctx)
		ui_show_warning_dialog("%s", fz_caught_message(ctx));

	if (pdf_update_page(ctx, selected_annot->page))
		render_page();
#else
	ui_show_warning_dialog("Document not signed as no LIBCRYPTO.");
#endif
}

static void cert_password_dialog(void)
{
	int is;
	ui_dialog_begin(400, (ui.gridsize+4)*3);
	{
		ui_layout(T, X, NW, 2, 2);
		ui_label("Password:");
		is = ui_input(&cert_password, 200, 1);

		ui_layout(B, X, NW, 2, 2);
		ui_panel_begin(0, ui.gridsize, 0, 0, 0);
		{
			ui_layout(R, NONE, S, 0, 0);
			if (ui_button("Cancel"))
				ui.dialog = NULL;
			ui_spacer();
			if (ui_button("Okay") || is == UI_INPUT_ACCEPT)
			{
				ui.dialog = NULL;
				do_sign();
			}
		}
		ui_panel_end();
	}
	ui_dialog_end();
}

static int cert_file_filter(const char *fn)
{
	return !!strstr(fn, ".pfx");
}

static void cert_file_dialog(void)
{
	if (ui_open_file(cert_filename))
	{
		if (cert_filename[0] != 0)
		{
			ui_input_init(&cert_password, "");
			ui.focus = &cert_password;
			ui.dialog = cert_password_dialog;
		}
		else
			ui.dialog = NULL;
	}
}

void do_widget_panel(void)
{
	int ff, type;
	char *value;

	ff = pdf_get_field_flags(ctx, selected_annot->page->doc, selected_annot->obj);
	type = pdf_field_type(ctx, selected_annot->page->doc, selected_annot->obj);

	if (type == PDF_WIDGET_TYPE_TEXT)
	{
		static pdf_annot *last_annot = NULL;
		static struct input input;
		ui_label("Value:");
		if (selected_annot != last_annot)
		{
			last_annot = selected_annot;
			value = pdf_field_value(ctx, selected_annot->page->doc, selected_annot->obj);
			ui_input_init(&input, value);
			fz_free(ctx, value);
		}
		if (ui_input(&input, 0, (ff & Ff_Multiline) ? 5 : 1) >= UI_INPUT_EDIT)
		{
			pdf_field_set_value(ctx, selected_annot->page->doc, selected_annot->obj, input.text);
			if (pdf_update_page(ctx, selected_annot->page))
				render_page();
		}
	}
	else if (type == PDF_WIDGET_TYPE_COMBOBOX || type == PDF_WIDGET_TYPE_LISTBOX)
	{
		char **options;
		int n, choice;
		ui_label("Value:");
		n = pdf_choice_widget_options(ctx, selected_annot->page->doc, selected_annot, 0, NULL);
		options = fz_malloc_array(ctx, n, sizeof(char*));
		pdf_choice_widget_options(ctx, selected_annot->page->doc, selected_annot, 0, options);
		value = pdf_field_value(ctx, selected_annot->page->doc, selected_annot->obj);
		choice = ui_select("Widget/Ch", value, options, n);
		if (choice >= 0)
		{
			pdf_field_set_value(ctx, selected_annot->page->doc, selected_annot->obj, options[choice]);
			if (pdf_update_page(ctx, selected_annot->page))
				render_page();
		}
		fz_free(ctx, value);
		fz_free(ctx, options);
	}
	else if (type == PDF_WIDGET_TYPE_SIGNATURE)
	{
		if (ui_button("Verify"))
		{
			char status[100];
			int result;
			result = pdf_check_signature(ctx, pdf, selected_annot, status, sizeof status);
			if (result)
				ui_show_warning_dialog("Signature is valid.\n%s", status);
			else
				ui_show_warning_dialog("Could not verify signature:\n%s", status);
		}
		if (ui_button("Sign"))
		{
			fz_strlcpy(cert_filename, filename, sizeof cert_filename);
			ui_init_open_file(".", cert_file_filter);
			ui.dialog = cert_file_dialog;
		}
	}
	else
	{
		value = pdf_field_value(ctx, pdf, selected_annot->obj);
		ui_label("Value: %s", value);
		fz_free(ctx, value);
	}
}
