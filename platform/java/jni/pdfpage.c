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
// Artifex Software, Inc., 1305 Grant Avenue - Suite 200, Novato,
// CA 94945, U.S.A., +1(415)492-9861, for further information.

/* PDFPage interface */

JNIEXPORT jobject JNICALL
FUN(PDFPage_createAnnotation)(JNIEnv *env, jobject self, jint subtype)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_annot *annot = NULL;

	if (!ctx || !page) return NULL;

	fz_try(ctx)
		annot = pdf_create_annot(ctx, page, subtype);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_PDFAnnotation_safe_own(ctx, env, annot);
}

JNIEXPORT void JNICALL
FUN(PDFPage_deleteAnnotation)(JNIEnv *env, jobject self, jobject jannot)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_annot *annot = from_PDFAnnotation(env, jannot);

	if (!ctx || !page) return;

	fz_try(ctx)
		pdf_delete_annot(ctx, page, annot);
	fz_catch(ctx)
		jni_rethrow_void(env, ctx);
}

JNIEXPORT jboolean JNICALL
FUN(PDFPage_update)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	jboolean changed = JNI_FALSE;

	if (!ctx || !page) return JNI_FALSE;

	fz_try(ctx)
		changed = pdf_update_page(ctx, page);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return changed;
}

JNIEXPORT jboolean JNICALL
FUN(PDFPage_applyRedactions)(JNIEnv *env, jobject self, jboolean blackBoxes, jint imageMethod)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	jboolean redacted = JNI_FALSE;
	pdf_redact_options opts = { blackBoxes, imageMethod };

	if (!ctx || !page) return JNI_FALSE;

	fz_try(ctx)
		redacted = pdf_redact_page(ctx, page->doc, page, &opts);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return redacted;
}

JNIEXPORT jobject JNICALL
FUN(PDFPage_getAnnotations)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_annot *annot = NULL;
	pdf_annot *annots = NULL;
	jobject jannots = NULL;
	int count;
	int i;

	if (!ctx || !page) return NULL;

	/* count the annotations */
	fz_try(ctx)
	{
		annots = pdf_first_annot(ctx, page);

		annot = annots;
		for (count = 0; annot; count++)
			annot = pdf_next_annot(ctx, annot);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	/* no annotations, return NULL instead of empty array */
	if (count == 0)
		return NULL;

	/* now run through actually creating the annotation objects */
	jannots = (*env)->NewObjectArray(env, count, cls_PDFAnnotation, NULL);
	if (!jannots || (*env)->ExceptionCheck(env)) jni_throw_null(env, "cannot wrap page annotations in object array");

	annot = annots;
	for (i = 0; annot && i < count; i++)
	{
		jobject jannot = to_PDFAnnotation_safe(ctx, env, annot);
		if (!jannot) return NULL;

		(*env)->SetObjectArrayElement(env, jannots, i, jannot);
		if ((*env)->ExceptionCheck(env)) return NULL;

		(*env)->DeleteLocalRef(env, jannot);

		fz_try(ctx)
			annot = pdf_next_annot(ctx, annot);
		fz_catch(ctx)
			jni_rethrow(env, ctx);
	}

	return jannots;
}

JNIEXPORT jobjectArray JNICALL
FUN(PDFPage_getWidgets)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_annot *widget = NULL;
	pdf_annot *widgets = NULL;
	jobjectArray jwidgets = NULL;
	int count;
	int i;

	if (!ctx || !page) return NULL;

	/* count the widgets */
	fz_try(ctx)
	{
		widgets = pdf_first_widget(ctx, page);

		widget = widgets;
		for (count = 0; widget; count++)
			widget = pdf_next_widget(ctx, widget);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	/* no widgegts, return NULL instead of empty array */
	if (count == 0)
		return NULL;

	/* now run through actually creating the widget objects */
	jwidgets = (*env)->NewObjectArray(env, count, cls_PDFWidget, NULL);
	if (!jwidgets || (*env)->ExceptionCheck(env)) jni_throw_null(env, "cannot wrap page widgets in object array");

	widget = widgets;
	for (i = 0; widget && i < count; i++)
	{
		jobject jwidget = NULL;

		if (widget)
		{
			jwidget = to_PDFWidget_safe(ctx, env, widget);
			if (!jwidget) return NULL;
		}

		(*env)->SetObjectArrayElement(env, jwidgets, i, jwidget);
		if ((*env)->ExceptionCheck(env)) return NULL;

		(*env)->DeleteLocalRef(env, jwidget);

		fz_try(ctx)
			widget = pdf_next_widget(ctx, widget);
		fz_catch(ctx)
			jni_rethrow(env, ctx);
	}

	return jwidgets;
}

JNIEXPORT jobject JNICALL
FUN(PDFPage_createSignature)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_annot *widget = NULL;
	char name[80];

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
	{
		pdf_create_field_name(ctx, page->doc, "Signature", name, sizeof name);
		widget = pdf_create_signature_widget(ctx, page, name);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}

	return to_PDFWidget_safe_own(ctx, env, widget);
}

JNIEXPORT jobject JNICALL
FUN(PDFPage_getTransform)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	fz_matrix ctm;

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
		pdf_page_transform(ctx, page, NULL, &ctm);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Matrix_safe(ctx, env, ctm);
}

JNIEXPORT jobject JNICALL
FUN(PDFPage_createLink)(JNIEnv *env, jobject self, jobject jrect, jint pageno, jint type, jobject jargs)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	fz_rect rect = from_Rect(env, jrect);
	fz_link *link = NULL;
	char *uri = NULL;
	jsize argcount;
	jfloat *args = NULL;
	float arg1 = 1;
	float arg2 = 2;
	float arg3 = 3;
	float arg4 = 4;

	if (!ctx || !page)
		return NULL;

	argcount = (*env)->GetArrayLength(env, jargs);
	args = (*env)->GetFloatArrayElements(env, jargs, NULL);
	if (!args) jni_throw_io(env, "cannot get floats arguments to pass");

	fz_try(ctx)
	{
		switch (argcount)
		{
		default:
		case 4: arg4 = args[3]; /* fallthrough */
		case 3: arg3 = args[2]; /* fallthrough */
		case 2: arg2 = args[1]; /* fallthrough */
		case 1: arg1 = args[0]; /* fallthrough */
		case 0: break;
		}
		pageno = fz_clampi(pageno, 0, pdf_count_pages(ctx, page->doc) - 1);
		uri = pdf_new_link_uri(ctx, pageno, type, arg1, arg2, arg3, arg4);
		link = fz_create_link(ctx, &page->super, rect, uri);
	}
	fz_always(ctx)
	{
		fz_free(ctx, uri);
		(*env)->ReleaseFloatArrayElements(env, jargs, args, 0);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Link_safe_own(ctx, env, link);
}
