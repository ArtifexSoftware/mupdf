/*
 * PDF creation tool: Tool for creating pdf content.
 *
 * Simple test bed to work with adding content and creating PDFs
 *
 */

#include "mupdf/pdf.h"

#define MAX_IMAGES 10
#define MAX_FONTS 10
#define MAX_REF_NAME 32

enum { RES_FONT, RES_XOBJECT };

static void usage(void)
{
	fprintf(stderr,
		"usage: mutool create [-o output.pdf] [fonts][images] contents\n"
		"\t-f\tfont label:font file\n"
		"\t-i\timage label:image file\n"
		"\tcontents file, defines page size, graphics, references fonts and images\n"
		);
	exit(1);
}

/* Simple structures to hold and manage contents */
typedef struct doc_content_s doc_content;
typedef struct resources_s resources;
typedef struct page_resource_xref_s page_resource_xref;

struct page_resource_xref_s
{
	char *res_name;
	char res_ref[MAX_REF_NAME];
	pdf_obj *obj;
	int type;
};

struct resources_s
{
	char *name;
	int ref;
};

struct doc_content_s
{
	fz_stream *stm;
	int num_pages;
	fz_point *page_sizes;
	fz_off_t *content_offsets;
	int *content_lengths;
	resources *fonts;
	int num_fonts;
	resources *images;
	int num_images;
	page_resource_xref **ref_im_resources;
	page_resource_xref **ref_font_resources;
	int *num_page_im_res;
	int *num_page_font_res;
};

/* Look for the presence of image or font refererences in the content */
static void check_for_reference(fz_context *ctx, resources *resource, int num_res, char *buffer, int res_type, doc_content *doc, int page_num)
{
	int i;
	char * pch;
	int length;
	char name[MAX_REF_NAME];
	int res_num;

	for (i = 0; i < num_res; i++)
	{
		pch = strchr(resource[i].name, ':');
		if (pch != NULL)
		{
			length = pch - resource[i].name;
			if (length < sizeof(name))
			{
				memcpy(name, resource[i].name, length);
				name[length] = 0;
				pch = strstr(buffer, name);
				if (pch != NULL)
				{
					/* Resource reference is in the content for this document. Mark
					 * it as such so that we know to add it to the document */
					resource[i].ref = 1;

					/* Also note this page has a reference to this name so
					 * we can add it to the page resource list.  Select from
					 * font or image */
					if (res_type == RES_FONT)
					{
						res_num = doc->num_page_font_res[page_num];
						doc->ref_font_resources[page_num][res_num].obj = NULL; /* Set later */
						doc->ref_font_resources[page_num][res_num].res_name = resource[i].name;
						doc->ref_font_resources[page_num][res_num].type = res_type;
						memcpy(doc->ref_font_resources[page_num][res_num].res_ref, name, sizeof(name));
						doc->num_page_font_res[page_num] += 1;
					}
					else
					{
						res_num = doc->num_page_im_res[page_num];
						doc->ref_im_resources[page_num][res_num].obj = NULL; /* Set later */
						doc->ref_im_resources[page_num][res_num].res_name = resource[i].name;
						doc->ref_im_resources[page_num][res_num].type = res_type;
						memcpy(doc->ref_im_resources[page_num][res_num].res_ref, name, sizeof(name));
						doc->num_page_im_res[page_num] += 1;
					}
				}
			}
			else
				fz_throw(ctx, FZ_ERROR_GENERIC, "Image/Font indirect name too long");
		}
		else
			fz_throw(ctx, FZ_ERROR_GENERIC, "Internal parsing error");
	}
}

static void drop_ref_objs(fz_context *ctx, page_resource_xref *refs, int num_refs)
{
	int i;

	for (i = 0; i < num_refs; i++)
		pdf_drop_obj(ctx, refs[i].obj);
}

static void free_contents(fz_context *ctx, doc_content *content)
{
	int i;

	fz_free(ctx, content->content_offsets);
	fz_free(ctx, content->content_lengths);
	fz_free(ctx, content->page_sizes);
	for (i = 0; i < content->num_pages; i++)
	{
		drop_ref_objs(ctx, content->ref_font_resources[i], content->num_page_font_res[i]);
		fz_free(ctx, content->ref_font_resources[i]);
	}
	fz_free(ctx, content->ref_font_resources);
	for (i = 0; i < content->num_pages; i++)
	{
		drop_ref_objs(ctx, content->ref_im_resources[i], content->num_page_im_res[i]);
		fz_free(ctx, content->ref_im_resources[i]);
	}
	fz_free(ctx, content->num_page_im_res);
	fz_free(ctx, content->num_page_font_res);
	fz_free(ctx, content->ref_im_resources);
	content->content_offsets = NULL;
	content->page_sizes = NULL;
	content->content_lengths = NULL;
	fz_drop_stream(ctx, content->stm);
}

/* This is a VERY simple format to give us something to play with
 * in terms of defining pages and content. Here we parse the contents
 * defining our page sizes and the command locations for each page.
 * The format is as follows:
 * 1) Comment lines are preceded by %
 * 2) Number of pages is indicated at the begining with /Pages #
 * 3) Each page is indicated by /Page # [X Y] (# is zero based)
 * 4) The content is in the form of simple PDF content stream that
 *    may included various drawing commands and reference the
 *    image and font resources.
 * */
static void init_parse_contents(fz_context *ctx, char *content_fn, doc_content *content)
{
	fz_stream *stm;
	char buf[1024];
	int page_count = 0;
	fz_off_t pre_off;
	int i;

	fz_var(stm);

	fz_try(ctx)
	{
		stm = fz_open_file(ctx, content_fn);
		while (1)
		{
			pre_off = fz_tell(ctx, stm);
			fz_read_line(ctx, stm, buf, sizeof buf);
			if (buf[0] == '\0')
			{
				if (content->num_pages > (page_count + 1))
					fz_throw(ctx, FZ_ERROR_GENERIC, "Missing defined pages");
				else
				{
					content->content_lengths[page_count - 1] =
						fz_tell(ctx, stm) - content->content_offsets[page_count - 1];
				}
				break;
			}
			if (buf[0] != '%')
			{
				if (strncmp(buf, "/Pages", strlen("/Pages")) == 0)
				{
					if ((content->num_pages = atoi(&(buf[strlen("/Pages")]))) <= 0)
						fz_throw(ctx, FZ_ERROR_GENERIC, "Page count invalid");
					content->content_offsets = fz_malloc_array(ctx, content->num_pages, sizeof(fz_off_t));
					content->content_lengths = fz_malloc_array(ctx, content->num_pages, sizeof(int));
					content->page_sizes = fz_malloc_array(ctx, content->num_pages, sizeof(fz_point));
					content->num_page_im_res = fz_calloc(ctx, content->num_pages, sizeof(int));
					content->num_page_font_res = fz_calloc(ctx, content->num_pages, sizeof(int));
					content->ref_font_resources = fz_malloc_array(ctx, content->num_pages, sizeof(page_resource_xref*));
					content->ref_im_resources = fz_malloc_array(ctx, content->num_pages, sizeof(page_resource_xref*));
					for (i = 0; i < content->num_pages; i++)
					{
						content->ref_font_resources[i] = fz_malloc_array(ctx, MAX_FONTS, sizeof(page_resource_xref));
						content->ref_im_resources[i] = fz_malloc_array(ctx, MAX_FONTS, sizeof(page_resource_xref));
					}
				}
				else if (strncmp(buf, "/Page", strlen("/Page")) == 0)
				{
					int page_num;
					if (page_count > 0)
					{
						content->content_lengths[page_count - 1] =
							(int)(pre_off - content->content_offsets[page_count - 1]);
					}
					if (sscanf(&(buf[strlen("/Page")]), "%d [%f %f]", &page_num,
						&(content->page_sizes[page_count].x), &(content->page_sizes[page_count].y)) != 3)
						fz_throw(ctx, FZ_ERROR_GENERIC, "Page size invalid");
					if (page_num < 0 || page_num >= content->num_pages)
						fz_throw(ctx, FZ_ERROR_GENERIC, "Page value invalid");
					if (content->page_sizes[page_count].x < 0 || content->page_sizes[page_count].y < 0)
						fz_throw(ctx, FZ_ERROR_GENERIC, "Page dimensions invalid");
					content->content_offsets[page_count] = fz_tell(ctx, stm);
					page_count++;
				}
				else
				{
					check_for_reference(ctx, content->images, content->num_images, buf, RES_XOBJECT, content, page_count - 1);
					check_for_reference(ctx, content->fonts, content->num_fonts, buf, RES_FONT, content, page_count - 1);
				}
			}
		}
	}
	fz_catch(ctx)
	{
		free_contents(ctx, content);
		fz_drop_stream(ctx, stm);
		fz_rethrow(ctx);
	}
	content->stm = stm;
}

/* Get the page contents */
static int get_page_contents(fz_context *ctx, int page_num, doc_content *content,
	unsigned char *buffer)
{
	int size = content->content_lengths[page_num];

	if (buffer == NULL)
		return size;
	fz_seek(ctx, content->stm, content->content_offsets[page_num], SEEK_SET);
	fz_read(ctx, content->stm, buffer, size);
	return size;
}

static void update_res(fz_context *ctx, int num_pages, int *num_res, page_resource_xref **page_resource,
	char *res_name, pdf_obj *obj)
{
	int j, i;

	for (j = 0; j < num_pages; j++)
		for (i = 0; i < num_res[j]; i++)
			if (strcmp(res_name, page_resource[j][i].res_name) == 0)
				page_resource[j][i].obj = obj;
}

static pdf_obj* create_page_res_dict(fz_context *ctx, pdf_document *pdf,
	page_resource_xref *ref_res, const char type[], int num_items)
{
	pdf_obj *dict = NULL;
	int i;

	if (num_items <= 0)
		return NULL;

	fz_var(dict);

	fz_try(ctx)
	{
		dict = pdf_new_dict(ctx, pdf, num_items);
		for (i = 0; i < num_items; i++)
		{
			char text[32];
			snprintf(text, sizeof(text), "%s/%s", type, ref_res[i].res_ref);
			pdf_dict_putp(ctx, dict, text, ref_res[i].obj);
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, dict);
		fz_rethrow(ctx);
	}
	return dict;
}

static int create_pdf(fz_context *ctx, char *output, resources fonts[], int num_fonts,
	resources images[], int num_images, char *contents)
{
	fz_rect bounds;
	pdf_document *pdf = NULL;
	pdf_page *newpage = NULL;
	unsigned char *buffer = NULL;
	fz_buffer *fz_buf = NULL;
	fz_buffer *im_font_buff = NULL;
	fz_image *image = NULL;
	pdf_obj *font_dict = NULL;
	pdf_obj *im_dict = NULL;
	pdf_res *im_res = NULL;
	pdf_res *font_res = NULL;
	pdf_write_options opts = { 0 };
	doc_content content = { 0 };
	int k;
	int length;
	char *pch;

	fz_var(pdf);
	fz_var(newpage);
	fz_var(buffer);
	fz_var(fz_buf);
	fz_var(im_font_buff);
	fz_var(image);
	fz_var(font_dict);
	fz_var(im_dict);
	fz_var(im_res);
	fz_var(font_res);

	fz_try(ctx)
	{
		pdf = pdf_create_document(ctx);
		content.num_fonts = num_fonts;
		content.num_images = num_images;
		content.fonts = fonts;
		content.images = images;
		init_parse_contents(ctx, contents, &content);

		/* Add the resources, getting the reference numbers in the process. */
		for (k = 0; k < content.num_images; k++)
		{
			if (content.images[k].ref)
			{
				/* Get the fz_image */
				pch = strchr(content.images[k].name, ':');
				if (pch != NULL)
				{
					im_font_buff = fz_read_file(ctx, &(pch[1]));
					image = fz_new_image_from_buffer(ctx, im_font_buff);
					fz_drop_buffer(ctx, im_font_buff);
					im_font_buff = NULL;
					im_res = pdf_add_image_res(ctx, pdf, image, 0);
					fz_drop_image(ctx, image);
					image = NULL;

					/* Look through our image page resources and update the
					 * indirect reference number. Here we don't use the numbers
					 * set by the doc resource holder (i.e im_res->num) since we
					 * are using our own content specified for pdfcreate */
					update_res(ctx, content.num_pages, content.num_page_im_res,
						content.ref_im_resources, content.images[k].name, im_res->obj);
				}
				else
					fz_throw(ctx, FZ_ERROR_GENERIC, "Image indirect name too long");
			}
		}
		for (k = 0; k < content.num_fonts; k++)
		{
			if (content.fonts[k].ref)
			{
				pch = strchr(content.fonts[k].name, ':');
				if (pch != NULL)
				{
					im_font_buff = fz_read_file(ctx, &(pch[1]));
					font_res = pdf_add_simple_font_res(ctx, pdf, im_font_buff);
					fz_drop_buffer(ctx, im_font_buff);
					im_font_buff = NULL;

					/* Look through our font page resources and update the indirect
					 * reference number */
					update_res(ctx, content.num_pages, content.num_page_font_res,
						content.ref_font_resources, content.fonts[k].name, font_res->obj);
				}
				else
					fz_throw(ctx, FZ_ERROR_GENERIC, "Font indirect name too long");
			}
		}

		/* Now the page contents */
		for (k = 0; k < content.num_pages; k++)
		{
			bounds.x0 = 0;
			bounds.y0 = 0;
			bounds.x1 = content.page_sizes[k].x;
			bounds.y1 = content.page_sizes[k].y;

			length = get_page_contents(ctx, k, &content, NULL);
			if (length > 0)
			{
				buffer = fz_malloc(ctx, length);
				length = get_page_contents(ctx, k, &content, buffer);
				fz_buf = fz_new_buffer_from_data(ctx, buffer, length);
				buffer = NULL;
				newpage = pdf_create_page(ctx, pdf, bounds, 0, fz_buf);
				/* Create the dicts for the page resources */
				font_dict = create_page_res_dict(ctx, pdf, content.ref_font_resources[k],
					"Font", content.num_page_font_res[k]);
				im_dict = create_page_res_dict(ctx, pdf, content.ref_im_resources[k],
					"XObject", content.num_page_im_res[k]);
				if (im_dict != NULL)
				{
					pdf_dict_puts(ctx, newpage->me, "Resources", im_dict);
					pdf_drop_obj(ctx, im_dict);
				}
				if (font_dict != NULL)
				{
					pdf_dict_puts(ctx, newpage->me, "Resources", font_dict);
					pdf_drop_obj(ctx, font_dict);
				}
				fz_drop_buffer(ctx, fz_buf);
				fz_buf = NULL;
			}
			else
			{
				newpage = pdf_create_page(ctx, pdf, bounds, 0, NULL);
			}
			pdf_insert_page(ctx, pdf, newpage, INT_MAX);
			pdf_drop_page(ctx, newpage);
			newpage = NULL;
		}
		pdf_save_document(ctx, pdf, output, &opts);
	}
	fz_always(ctx)
	{
		pdf_drop_page(ctx, newpage);
		pdf_close_document(ctx, pdf);
		free_contents(ctx, &content);
		fz_free(ctx, buffer);
		fz_drop_buffer(ctx, fz_buf);
		fz_drop_buffer(ctx, im_font_buff);
		fz_drop_image(ctx, image);
	}
	fz_catch(ctx)
	{
		fz_rethrow(ctx);
	}
	return 0;
}

int pdfcreate_main(int argc, char **argv)
{
	char *outfile = "out.pdf";
	resources fonts[MAX_FONTS];
	resources images[MAX_IMAGES];
	char *contents = "";
	int nfonts = 0;
	int nimages = 0;
	int c;
	int errors = 0;
	fz_context *ctx;

	while ((c = fz_getopt(argc, argv, "f:i:o:")) != -1)
	{
		switch (c)
		{
		case 'f':
			if (nfonts == MAX_FONTS)
			{
				fprintf(stderr, "max number of fonts exceeded\n");
				exit(1);
			}
			fonts[nfonts].name = fz_optarg;
			fonts[nfonts].ref = 0;
			nfonts++;
			break;
		case 'i':
			if (nimages == MAX_IMAGES)
			{
				fprintf(stderr, "max number of images exceeded\n");
				exit(1);
			}
			images[nimages].name = fz_optarg;
			images[nimages].ref = 0;
			nimages++;
			break;
		case 'o': outfile = fz_optarg; break;
		default: usage(); break;
		}
	}

	if (fz_optind == argc)
		usage();

	contents = argv[fz_optind++];

	ctx = fz_new_context(NULL, NULL, FZ_STORE_UNLIMITED);
	if (!ctx)
	{
		fprintf(stderr, "cannot initialise context\n");
		exit(1);
	}

	fz_try(ctx)
	{
		create_pdf(ctx, outfile, fonts, nfonts, images, nimages, contents);
	}
	fz_catch(ctx)
	{
		errors++;
	}
	fz_drop_context(ctx);

	return errors != 0;
}
