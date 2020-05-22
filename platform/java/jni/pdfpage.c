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
		return jni_rethrow(env, ctx), NULL;

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
		return jni_rethrow(env, ctx);
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
		return jni_rethrow(env, ctx), JNI_FALSE;

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
		return jni_rethrow(env, ctx), JNI_FALSE;

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
	int annot_count;
	int i;

	if (!ctx || !page) return NULL;

	/* count the annotations */
	fz_try(ctx)
	{
		annots = pdf_first_annot(ctx, page);

		annot = annots;
		for (annot_count = 0; annot; annot_count++)
			annot = pdf_next_annot(ctx, annot);
	}
	fz_catch(ctx)
		return jni_rethrow(env, ctx), NULL;

	/* no annotations, return NULL instead of empty array */
	if (annot_count == 0)
		return NULL;

	/* now run through actually creating the annotation objects */
	jannots = (*env)->NewObjectArray(env, annot_count, cls_PDFAnnotation, NULL);
	if (!jannots || (*env)->ExceptionCheck(env)) return NULL;

	annot = annots;
	for (i = 0; annot && i < annot_count; i++)
	{
		jobject jannot = to_PDFAnnotation_safe(ctx, env, annot);
		if (!jannot) return NULL;

		(*env)->SetObjectArrayElement(env, jannots, i, jannot);
		if ((*env)->ExceptionCheck(env)) return NULL;

		(*env)->DeleteLocalRef(env, jannot);

		fz_try(ctx)
			annot = pdf_next_annot(ctx, annot);
		fz_catch(ctx)
			return jni_rethrow(env, ctx), NULL;
	}

	return jannots;
}

JNIEXPORT jobjectArray JNICALL
FUN(PDFPage_getWidgetsNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_page *page = from_PDFPage(env, self);
	pdf_widget *widget;
	jobjectArray jwidgets = NULL;
	int count = 0;

	if (!ctx || !page) return NULL;

	fz_try(ctx)
		for (widget = pdf_first_widget(ctx, page); widget; widget = pdf_next_widget(ctx, widget))
			count++;
	fz_catch(ctx)
		count = 0;

	if (count == 0)
		return NULL;

	jwidgets = (*env)->NewObjectArray(env, count, cls_PDFWidget, NULL);
	if (!jwidgets || (*env)->ExceptionCheck(env)) return NULL;

	fz_try(ctx)
	{
		int i = 0;

		for (widget = pdf_first_widget(ctx, page); widget; widget = pdf_next_widget(ctx, widget))
		{
			jobject jwidget;

			jwidget = to_PDFWidget(ctx, env, widget);
			if (!jwidget)
				fz_throw_java(ctx, env);

			(*env)->SetObjectArrayElement(env, jwidgets, i, jwidget);
			if ((*env)->ExceptionCheck(env))
				fz_throw_java(ctx, env);

			(*env)->DeleteLocalRef(env, jwidget);
			i++;
		}
	}
	fz_catch(ctx)
		return jni_rethrow(env, ctx), NULL;

	return jwidgets;
}
