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
FUN(PDFPage_getWidgetsNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_widget *widget = NULL;
	pdf_widget *widgets = NULL;
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

static void get_fields_arrive_fn(fz_context *ctx, pdf_obj *obj, void *arg, pdf_obj **dummy)
{
	pdf_obj *fields = arg;
	if (pdf_name_eq(ctx, pdf_dict_get(ctx, obj, PDF_NAME(Type)), PDF_NAME(Annot))
		&& pdf_name_eq(ctx, pdf_dict_get(ctx, obj, PDF_NAME(Subtype)), PDF_NAME(Widget)))
	{
		pdf_array_push(ctx, fields, obj);
	}
}

static pdf_obj *get_fields(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *field_tree = pdf_dict_getp(ctx, pdf_trailer(ctx, doc), "Root/AcroForm/Fields");
	pdf_obj *fields = pdf_new_array(ctx, doc, 20);
	fz_try(ctx)
	{
		pdf_walk_tree(ctx, field_tree, PDF_NAME(Kids), get_fields_arrive_fn, NULL, fields, NULL, NULL);
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, fields);
		fz_rethrow(ctx);
	}
	return fields;
}

static pdf_obj *get_field_names(fz_context *ctx, pdf_document *doc)
{
	pdf_obj *fields = get_fields(ctx, doc);
	int n = pdf_array_len(ctx, fields);
	pdf_obj *field_names = NULL;
	char *name = NULL;
	fz_var(field_names);
	fz_var(name);
	fz_try(ctx)
	{
		int i;
		field_names = pdf_new_array(ctx, doc, n);
		for (i = 0; i < n; i++)
		{
			name = pdf_field_name(ctx, pdf_array_get(ctx, fields, i));
			pdf_array_push_drop(ctx, field_names, pdf_new_name(ctx, name));
			fz_free(ctx, name);
			name = NULL;
		}
	}
	fz_always(ctx)
	{
		pdf_drop_obj(ctx, fields);
	}
	fz_catch(ctx)
	{
		fz_free(ctx, name);
		pdf_drop_obj(ctx, field_names);
		fz_rethrow(ctx);
	}
	return field_names;
}

static void make_unused_field_name(fz_context *ctx, pdf_document *doc, const char *fmt, char *buffer)
{
	pdf_obj *field_names = get_field_names(ctx, doc);
	fz_try(ctx)
	{
		int x = 0;
		for (;;)
		{
			int i, n = pdf_array_len(ctx, field_names);
			sprintf(buffer, fmt, x);
			for (i = 0; i < n; i++)
			{
				if (strcmp(buffer, pdf_to_name(ctx, pdf_array_get(ctx, field_names, i))) == 0)
					break;
			}
			if (i == n)
				break;
			++x;
		}
	}
	fz_catch(ctx)
	{
		pdf_drop_obj(ctx, field_names);
		fz_rethrow(ctx);
	}
}

JNIEXPORT jobject JNICALL
FUN(PDFPage_createSignature)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_widget *widget = NULL;
	char name[80];

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
	{
		make_unused_field_name(ctx, page->doc, "Signature%d", name);
		widget = pdf_create_signature_widget(ctx, page, name);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}

	return to_PDFWidget_safe_own(ctx, env, widget);
}
