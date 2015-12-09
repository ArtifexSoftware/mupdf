#include <jni.h>
#include <time.h>
#include <pthread.h>
#include <android/log.h>
#include <android/bitmap.h>

#include <stdio.h>
#include <stdlib.h>
#include <math.h>

#ifdef NDK_PROFILER
#include "prof.h"
#endif

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#define MY_JNI_VERSION JNI_VERSION_1_6

#define JNI_FN(A) Java_com_artifex_mupdf_fitz_ ## A
#define PACKAGENAME "com.artifex.mupdf.fitz"
#define PACKAGEPATH "com/artifex/mupdf/fitz/"

#define LOG_TAG "libmupdf"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGT(...) __android_log_print(ANDROID_LOG_INFO,"alert",__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)

/* Set to 1 to enable debug log traces. */
#define DEBUG 0

/* All the cached classes/mids/fids we need */

static jclass annot_class;
static jfieldID annot_fid;
static jmethodID annot_const_mid;
static jclass cdevice_class;
static jfieldID cdevice_nativeresource_fid;
static jfieldID cdevice_nativeinfo_fid;
static jclass colorspace_class;
static jfieldID colorspace_fid;
static jmethodID colorspace_const_mid;
static jclass cookie_class;
static jfieldID cookie_fid;
static jclass device_class;
static jfieldID device_fid;
static jmethodID device_begin_page_mid;
static jmethodID device_end_page_mid;
static jmethodID device_fill_path_mid;
static jmethodID device_stroke_path_mid;
static jmethodID device_clip_path_mid;
static jmethodID device_clip_stroke_path_mid;
static jmethodID device_fill_text_mid;
static jmethodID device_stroke_text_mid;
static jmethodID device_clip_text_mid;
static jmethodID device_clip_stroke_text_mid;
static jmethodID device_ignore_text_mid;
static jmethodID device_fill_shade_mid;
static jmethodID device_fill_image_mid;
static jmethodID device_fill_image_mask_mid;
static jmethodID device_clip_image_mask_mid;
static jmethodID device_pop_clip_mid;
static jmethodID device_begin_mask_mid;
static jmethodID device_end_mask_mid;
static jmethodID device_begin_group_mid;
static jmethodID device_end_group_mid;
static jmethodID device_begin_tile_mid;
static jmethodID device_end_tile_mid;
static jclass displaylist_class;
static jfieldID displaylist_fid;
static jclass document_class;
static jfieldID document_fid;
static jclass exception_class;
static jclass font_class;
static jfieldID font_fid;
//static jfieldID font_isconst_fid;
static jclass image_class;
static jfieldID image_fid;
static jmethodID image_const_mid;
static jclass link_class;
static jfieldID link_fid;
static jclass matrix_class;
static jfieldID matrix_a_fid;
static jfieldID matrix_b_fid;
static jfieldID matrix_c_fid;
static jfieldID matrix_d_fid;
static jfieldID matrix_e_fid;
static jfieldID matrix_f_fid;
static jmethodID matrix_const_mid;
static jclass outline_class;
static jfieldID outline_fid;
static jmethodID outline_const_mid;
static jclass page_class;
static jfieldID page_fid;
static jmethodID page_const_mid;
static jfieldID page_document_fid;
static jfieldID page_annots_fid;
static jclass path_class;
static jfieldID path_fid;
static jmethodID path_const_mid;
static jclass pathproc_class;
static jmethodID pathproc_moveto_mid;
static jmethodID pathproc_lineto_mid;
static jmethodID pathproc_curveto_mid;
static jmethodID pathproc_close_mid;
static jclass point_class;
static jfieldID point_fid;
static jmethodID point_const_mid;
static jclass rect_class;
static jfieldID rect_x0_fid;
static jfieldID rect_x1_fid;
static jfieldID rect_y0_fid;
static jfieldID rect_y1_fid;
static jmethodID rect_const_mid;
static jclass shade_class;
static jfieldID shade_fid;
static jmethodID shade_const_mid;
static jclass stroke_class;
static jfieldID stroke_fid;
static jmethodID stroke_const_mid;
static jclass text_class;
static jfieldID text_fid;
static jmethodID text_const_mid;
static jclass trylaterexception_class;

static pthread_key_t context_key;
static fz_context *base_context;

static void
throwOutOfMemoryError(JNIEnv *env, const char *info)
{
	jclass oomCls = (*env)->FindClass(env, "java/lang/OutOfMemoryError");

	if (oomCls == NULL)
		return; /* Well, what hope have we got! */

	(*env)->ExceptionClear(env);
	(*env)->ThrowNew(env, oomCls, info);
}

static const char *last_class_obtained = NULL;

static jclass
get_class(int *failed, JNIEnv *env, const char *str)
{
	jclass local, global;

	if (*failed)
		return NULL;

	last_class_obtained = str;
	local = (*env)->FindClass(env, str);
	if (local == NULL)
	{
		LOGI("Failed to find class %s", str);
		*failed = 1;
		return NULL;
	}

	global = (*env)->NewGlobalRef(env, local);
	if (global == NULL)
	{
		LOGI("Failed to make global ref for %s", str);
		*failed = 1;
		return NULL;
	}

	(*env)->DeleteLocalRef(env, local);

	return global;
}

static jfieldID
get_field(int *failed, JNIEnv *env, jclass cla, const char *field, const char *sig)
{
	jfieldID fid;

	if (*failed || cla == NULL)
		return NULL;

	fid = (*env)->GetFieldID(env, cla, field, sig);
	if (fid == (jfieldID)0)
	{
		LOGI("Failed to get field for %s %s %s", last_class_obtained ? last_class_obtained : "<noclass>", field, sig);
		*failed = 1;
	}

	return fid;
}

static jmethodID
get_method(int *failed, JNIEnv *env, jclass cla, const char *method, const char *sig)
{
	jmethodID mid;

	if (*failed || cla == NULL)
		return NULL;

	mid = (*env)->GetMethodID(env, cla, method, sig);
	if (mid == (jmethodID)0)
	{
		LOGI("Failed to get method for %s %s %s", last_class_obtained ? last_class_obtained : "<noclass>", method, sig);
		*failed = 1;
	}

	return mid;
}

static int find_fids(JNIEnv *env)
{
	int failed = 0;

	annot_class = get_class(&failed, env, PACKAGEPATH"Annotation");
	annot_fid = get_field(&failed, env, annot_class, "nativeAnnot", "J");
	annot_const_mid = get_method(&failed, env, annot_class, "<init>", "(J)V");
	cdevice_class = get_class(&failed, env, PACKAGEPATH"CDevice");
	cdevice_nativeresource_fid = get_field(&failed, env, cdevice_class, "nativeResource", "Ljava.lang.Object;");
	cdevice_nativeinfo_fid = get_field(&failed, env, cdevice_class, "nativeInfo", "J");
	colorspace_class = get_class(&failed, env, PACKAGEPATH"ColorSpace");
	colorspace_fid = get_field(&failed, env, colorspace_class, "nativeColorSpace", "J");
	colorspace_const_mid = get_method(&failed, env, colorspace_class, "<init>", "(J)V");
	cookie_class = get_class(&failed, env, PACKAGEPATH"Cookie");
	cookie_fid = get_field(&failed, env, cookie_class, "nativeCookie", "J");
	device_class = get_class(&failed, env, PACKAGEPATH"Device");
	device_fid = get_field(&failed, env, device_class, "nativeDevice", "J");
	device_begin_page_mid = get_method(&failed, env, device_class, "beginPage", "(L"PACKAGEPATH"Rect;L"PACKAGEPATH"Matrix;)V");
	device_end_page_mid = get_method(&failed, env, device_class, "endPage", "()V");
	device_fill_path_mid = get_method(&failed, env, device_class, "fillPath", "(L"PACKAGEPATH"Path;IL"PACKAGEPATH"Matrix;L"PACKAGEPATH"ColorSpace;[FF)V");
	device_stroke_path_mid = get_method(&failed, env, device_class, "strokePath", "(JL"PACKAGEPATH"Path;L"PACKAGEPATH"StrokeState;L"PACKAGEPATH"Matrix;L"PACKAGEPATH"ColorSpace;[FF)V");
	device_clip_path_mid = get_method(&failed, env, device_class, "clipPath", "(L"PACKAGEPATH"Path;L"PACKAGEPATH"Rect;IL"PACKAGEPATH"Matrix;)V");
	device_clip_stroke_path_mid = get_method(&failed, env, device_class, "clipStrokePath", "(L"PACKAGEPATH"Path;L"PACKAGEPATH"Rect;L"PACKAGEPATH"StrokeState;L"PACKAGEPATH"Matrix;)V");
	device_fill_text_mid = get_method(&failed, env, device_class, "fillText", "(L"PACKAGEPATH"Text;L"PACKAGEPATH"Matrix;L"PACKAGEPATH"ColorSpace;[FF)V");
	device_stroke_text_mid = get_method(&failed, env, device_class, "strokeText", "(L"PACKAGEPATH"Text;L"PACKAGEPATH"StrokeState;L"PACKAGEPATH"Matrix;L"PACKAGEPATH"ColorSpace;[FF)V");
	device_clip_text_mid = get_method(&failed, env, device_class, "clipText", "(L"PACKAGEPATH"Text;L"PACKAGEPATH"Matrix;)V");
	device_clip_stroke_text_mid = get_method(&failed, env, device_class, "clipStrokeText", "(L"PACKAGEPATH"Text;L"PACKAGEPATH"StrokeState;L"PACKAGEPATH"Matrix;)V");
	device_ignore_text_mid = get_method(&failed, env, device_class, "ignoreText", "(L"PACKAGEPATH"Text;L"PACKAGEPATH"Matrix;)V");
	device_fill_shade_mid = get_method(&failed, env, device_class, "fillShade", "(L"PACKAGEPATH"Shade;L"PACKAGEPATH"Matrix;F)V");
	device_fill_image_mid = get_method(&failed, env, device_class, "fillImage", "(L"PACKAGEPATH"Image;L"PACKAGEPATH"Matrix;F)V");
	device_fill_image_mask_mid = get_method(&failed, env, device_class, "fillImageMask", "(L"PACKAGEPATH"Image;L"PACKAGEPATH"Matrix;L"PACKAGEPATH"ColorSpace;[FF)V");
	device_clip_image_mask_mid = get_method(&failed, env, device_class, "clipImageMask", "(L"PACKAGEPATH"Image;L"PACKAGEPATH"Rect;L"PACKAGEPATH"Matrix;)V");
	device_pop_clip_mid = get_method(&failed, env, device_class, "popClip", "()V");
	device_begin_mask_mid = get_method(&failed, env, device_class, "beginMask", "(L"PACKAGEPATH"Rect;IL"PACKAGEPATH"ColorSpace;[F)V");
	device_end_mask_mid = get_method(&failed, env, device_class, "endMask", "()V");
	device_begin_group_mid = get_method(&failed, env, device_class, "beginGroup", "(L"PACKAGEPATH"Rect;IIIF)V");
	device_end_group_mid = get_method(&failed, env, device_class, "endGroup", "()V");
	device_begin_tile_mid = get_method(&failed, env, device_class, "beginTile", "(L"PACKAGEPATH"Rect;L"PACKAGEPATH"Rect;FFL"PACKAGEPATH"Matrix;I)I");
	device_end_tile_mid = get_method(&failed, env, device_class, "endTile", "()V");
	exception_class = get_class(&failed, env, "java/lang/Exception");
	displaylist_class = get_class(&failed, env, PACKAGEPATH"DisplayList");
	displaylist_fid = get_field(&failed, env, displaylist_class, "nativeDisplayList", "J");
	document_class = get_class(&failed, env, PACKAGEPATH"Document");
	document_fid = get_field(&failed, env, document_class, "nativeDocument", "J");
	font_class = get_class(&failed, env, PACKAGEPATH"Font");
	font_fid = get_field(&failed, env, font_class, "nativeFont", "J");
	//font_isconst_fid = get_field(&failed, env, font_class, "isConst", "Z");
	image_class = get_class(&failed, env, PACKAGEPATH"Image");
	image_fid = get_field(&failed, env, image_class, "nativeImage", "J");
	image_const_mid = get_method(&failed, env, image_class, "<init>", "(J)V");
	link_class = get_class(&failed, env, PACKAGEPATH"Link");
	link_fid = get_field(&failed, env, link_class, "nativeLink", "J");
	matrix_class = get_class(&failed, env, PACKAGEPATH"Matrix");
	matrix_a_fid = get_field(&failed, env, matrix_class, "a", "F");
	matrix_b_fid = get_field(&failed, env, matrix_class, "b", "F");
	matrix_c_fid = get_field(&failed, env, matrix_class, "c", "F");
	matrix_d_fid = get_field(&failed, env, matrix_class, "d", "F");
	matrix_e_fid = get_field(&failed, env, matrix_class, "e", "F");
	matrix_f_fid = get_field(&failed, env, matrix_class, "f", "F");
	matrix_const_mid = get_method(&failed, env, matrix_class, "<init>", "(FFFFFF)V");
	outline_class = get_class(&failed, env, PACKAGEPATH"Outline");
	outline_fid = get_field(&failed, env, outline_class, "nativeOutline", "J");
	outline_const_mid = get_method(&failed, env, outline_class, "<init>", "(J)V");
	page_class = get_class(&failed, env, PACKAGEPATH"Page");
	page_fid = get_field(&failed, env, page_class, "nativePage", "J");
	page_const_mid = get_method(&failed, env, page_class, "<init>", "(J)V");
	page_annots_fid = get_field(&failed, env, page_class, "nativeAnnots", "[L"PACKAGEPATH"Annotation;");
	path_class = get_class(&failed, env, PACKAGEPATH"Path");
	path_fid = get_field(&failed, env, path_class, "nativePath", "J");
	path_const_mid = get_method(&failed, env, path_class, "<init>", "(J)V");
	point_class = get_class(&failed, env, PACKAGEPATH"Point");
	point_const_mid = get_method(&failed, env, point_class, "<init>", "(FF)V");
	pathproc_class = get_class(&failed, env, PACKAGEPATH"PathProcessor");
	pathproc_moveto_mid = get_method(&failed, env, pathproc_class, "moveTo", "(FF)V");
	pathproc_lineto_mid = get_method(&failed, env, pathproc_class, "lineTo", "(FF)V");
	pathproc_curveto_mid = get_method(&failed, env, pathproc_class, "curveTo", "(FFFFFF)V");
	pathproc_close_mid = get_method(&failed, env, pathproc_class, "close", "()V");
	rect_class = get_class(&failed, env, PACKAGEPATH"Rect");
	rect_x0_fid = get_field(&failed, env, rect_class, "x0", "F");
	rect_x1_fid = get_field(&failed, env, rect_class, "x1", "F");
	rect_y0_fid = get_field(&failed, env, rect_class, "y0", "F");
	rect_y1_fid = get_field(&failed, env, rect_class, "y1", "F");
	rect_const_mid = get_method(&failed, env, rect_class, "<init>", "(FFFF)V");
	shade_class = get_class(&failed, env, PACKAGEPATH"Shade");
	shade_fid = get_field(&failed, env, shade_class, "nativeShade", "J");
	shade_const_mid = get_method(&failed, env, shade_class, "<init>", "(J)V");
	stroke_class = get_class(&failed, env, PACKAGEPATH"StrokeState");
	stroke_fid = get_field(&failed, env, stroke_class, "nativeStroke", "J");
	stroke_const_mid = get_method(&failed, env, stroke_class, "<init>", "(J)V");
	text_class = get_class(&failed, env, PACKAGEPATH"Text");
	text_fid = get_field(&failed, env, text_class, "nativeText", "J");
	text_const_mid = get_method(&failed, env, text_class, "<init>", "(J)V");
	trylaterexception_class = get_class(&failed, env, PACKAGEPATH"TryLaterException");

	return failed;
}

static void lose_fids(JNIEnv *env)
{
	(*env)->DeleteGlobalRef(env, annot_class);
	(*env)->DeleteGlobalRef(env, cdevice_class);
	(*env)->DeleteGlobalRef(env, colorspace_class);
	(*env)->DeleteGlobalRef(env, cookie_class);
	(*env)->DeleteGlobalRef(env, device_class);
	(*env)->DeleteGlobalRef(env, displaylist_class);
	(*env)->DeleteGlobalRef(env, document_class);
	(*env)->DeleteGlobalRef(env, exception_class);
	(*env)->DeleteGlobalRef(env, font_class);
	(*env)->DeleteGlobalRef(env, image_class);
	(*env)->DeleteGlobalRef(env, link_class);
	(*env)->DeleteGlobalRef(env, matrix_class);
	(*env)->DeleteGlobalRef(env, outline_class);
	(*env)->DeleteGlobalRef(env, page_class);
	(*env)->DeleteGlobalRef(env, path_class);
	(*env)->DeleteGlobalRef(env, pathproc_class);
	(*env)->DeleteGlobalRef(env, rect_class);
	(*env)->DeleteGlobalRef(env, shade_class);
	(*env)->DeleteGlobalRef(env, stroke_class);
	(*env)->DeleteGlobalRef(env, text_class);
	(*env)->DeleteGlobalRef(env, trylaterexception_class);
}

static pthread_mutex_t mutexes[FZ_LOCK_MAX];

static void lock(void *user, int lock)
{
	(void)pthread_mutex_lock(&mutexes[lock]);
}

static void unlock(void *user, int lock)
{
	(void)pthread_mutex_unlock(&mutexes[lock]);
}

static const fz_locks_context locks =
{
	NULL, /* user */
	lock,
	unlock
};

static void fin_context(void *ctx)
{
	fz_drop_context((fz_context *)ctx);
}

static int fin_base_context(JNIEnv *env)
{
	int i;

	for (i = 0; i < FZ_LOCK_MAX; i++)
		(void)pthread_mutex_destroy(&mutexes[i]);

	fz_drop_context(base_context);
	base_context = NULL;
}

static int init_base_context(JNIEnv *env)
{
	int i;

	for (i = 0; i < FZ_LOCK_MAX; i++)
		(void)pthread_mutex_init(&mutexes[i], NULL);

	base_context = fz_new_context(NULL, &locks, FZ_STORE_DEFAULT);
	if (base_context == NULL)
		return -1;

	fz_register_document_handlers(base_context);

	return 0;
}

static fz_context *get_context(JNIEnv *env)
{
	fz_context *ctx = (fz_context *)pthread_getspecific(context_key);

	if (ctx != NULL)
		return ctx;

	ctx = fz_clone_context(base_context);
	if (ctx == NULL)
	{
		throwOutOfMemoryError(env, "Failed to clone fz_context");
		return NULL;
	}
	pthread_setspecific(context_key, ctx);
	return ctx;
}

jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
	JNIEnv *env;

	if ((*vm)->GetEnv(vm, (void **)&env, MY_JNI_VERSION) != JNI_OK)
		return -1;

	/* Must init the context before find_finds, because the act of
	 * finding the fids can cause classes to load. This causes
	 * statics to be setup, which can in turn call JNI code, which
	 * requires the context. (For example see ColorSpace) */
	if (init_base_context(env) < 0)
		return -1;

	if (find_fids(env) != 0)
	{
		fin_base_context(env);
		return -1;
	}

	return MY_JNI_VERSION;
}

void JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env;

	if ((*vm)->GetEnv(vm, (void **)&env, MY_JNI_VERSION) != JNI_OK)
		return; /* If this fails, we're really in trouble! */

	fz_drop_context(base_context);
	base_context = NULL;
	lose_fids(env);
}

// Do our best to avoid casting warnings.
#define CAST(type, var) (type)pointer_cast(var)

static inline void *pointer_cast(jlong l)
{
	return (void *)(intptr_t)l;
}

static inline jlong jlong_cast(const void *p)
{
	return (jlong)(intptr_t)p;
}

/* Conversion functions: C to Java */
static inline jobject Annotation_from_fz_annot(fz_context *ctx, JNIEnv *env, fz_annot *annot)
{
	jobject jannot;

	if (ctx == NULL)
		return NULL;

	(*env)->NewObject(env, annot_class, annot_const_mid, annot);
	if (jannot == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "Annotation creation failed");

	return jannot;
}

static inline jobject ColorSpace_from_fz_colorspace(fz_context *ctx, JNIEnv *env, fz_colorspace *cs)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, colorspace_class, colorspace_const_mid, jlong_cast(cs));
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of ColorSpace failed");

	fz_keep_colorspace(ctx, cs);

	return jobj;
}

static inline jobject Image_from_fz_image(fz_context *ctx, JNIEnv *env, fz_image *img)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, image_class, image_const_mid, jlong_cast(img));
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Image failed");

	fz_keep_image(ctx, img);

	return jobj;
}

static inline jobject Matrix_from_fz_matrix(fz_context *ctx, JNIEnv *env, const fz_matrix *mat)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, matrix_class, matrix_const_mid, mat->a, mat->b, mat->c, mat->d, mat->e, mat->f);
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Matrix failed");

	return jobj;
}

static inline jobject Outline_from_fz_outline(fz_context *ctx, JNIEnv *env, fz_outline *outline)
{
	jobject joutline;

	if (ctx == NULL)
		return NULL;

	joutline = (*env)->NewObject(env, outline_class, outline_const_mid, jlong_cast(outline));
	if (joutline == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "getOutline failed (3)");

	return joutline;
}

static inline jobject Page_from_fz_page(fz_context *ctx, JNIEnv *env, fz_page *page)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, page_class, page_const_mid, jlong_cast(page));
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Page failed");

	return jobj;
}

static inline jobject Path_from_fz_path(fz_context *ctx, JNIEnv *env, fz_path *path)
{
	jobject jobj;
	fz_path *new_path;
	
	if (ctx == NULL)
		return NULL;

	new_path = fz_clone_path(ctx, path);

	jobj = (*env)->NewObject(env, path_class, path_const_mid, jlong_cast(new_path));
	if (jobj == NULL)
	{
		fz_drop_path(ctx, new_path);
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Path failed");
	}

	return jobj;
}

static inline jobject Point_from_fz_point(fz_context *ctx, JNIEnv *env, fz_point point)
{
	jobject jpoint;

	if (ctx == NULL)
		return NULL;

	jpoint = (*env)->NewObject(env, point_class, point_const_mid, point.x, point.y);
	if (jpoint == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "currentPoint failed (3)");

	return jpoint;
}

static inline jobject Rect_from_fz_rect(fz_context *ctx, JNIEnv *env, const fz_rect *rect)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, rect_class, rect_const_mid, rect->x0, rect->y0, rect->x1, rect->y1);
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Rect failed");

	return jobj;
}

static inline jobject Shade_from_fz_shade(fz_context *ctx, JNIEnv *env, fz_shade *shade)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, shade_class, shade_const_mid, jlong_cast(shade));
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Shade failed");

	fz_keep_shade(ctx, shade);

	return jobj;
}

static inline jobject StrokeState_from_fz_stroke_state(fz_context *ctx, JNIEnv *env, fz_stroke_state *state)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, stroke_class, stroke_const_mid, jlong_cast(state));
	if (jobj == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of StrokeState failed");

	fz_keep_stroke_state(ctx, state);

	return jobj;
}

static inline jobject Text_from_fz_text(fz_context *ctx, JNIEnv *env, fz_text *text)
{
	jobject jobj;
	fz_text *new_text;
	
	if (ctx == NULL)
		return NULL;

	new_text = fz_clone_text(ctx, text);

	jobj = (*env)->NewObject(env, text_class, text_const_mid, jlong_cast(new_text));
	if (jobj == NULL)
	{
		fz_drop_text(ctx, new_text);
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Text failed");
	}

	return jobj;
}

static inline jfloatArray jfloatArray_from_fz_color(fz_context *ctx, JNIEnv *env, float *color, int n)
{
	jfloatArray arr;

	if (ctx == NULL)
		return NULL;

	arr = (*env)->NewFloatArray(env, n);
	if (arr == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of floatArray failed");

	(*env)->SetFloatArrayRegion(env, arr, 0, n, color);

	return arr;
}

/* Devices can either be implemented in C, or in Java.
 *
 * We therefore have to think about 4 possible call combinations.
 *
 * 1) C -> C:       The standard mupdf case. No special worries here.
 * 2) C -> Java:    This can only happen when we call run on a page/annotation/
 *                  displaylist. We need to ensure that the java Device has an
 *                  appropriate fz_java_device generated for it. The 'run' calls
 *                  take care to lock/unlock for us.
 * 3) Java -> C:    The C device will have a java shim (a subclass of CDevice).
 *                  All calls will go through the device methods in CDevice,
 *                  which converts the java objects to C ones, and lock/unlock
 *                  any underlying objects as required.
 * 4) Java -> Java: No special worries.
 */

/* Our java device wrapping functions */

typedef struct
{
	fz_device base;
	JNIEnv *env;
	jobject self;
}
fz_java_device;

static void
fz_java_device_begin_page(fz_context *ctx, fz_device *dev, const fz_rect *rect, const fz_matrix *ctm)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_begin_page_mid, jrect, jctm);
}

static void
fz_java_device_end_page(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, device_end_page_mid);
}

static void
fz_java_device_fill_path(fz_context *ctx, fz_device *dev, fz_path *path, int even_odd, const fz_matrix *ctm, fz_colorspace *cs, float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = Path_from_fz_path(ctx, env, path);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	jfloatArray jcolor = jfloatArray_from_fz_color(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_fill_path_mid, jpath, even_odd, jctm, jcs, jcolor, alpha);
}

static void
fz_java_device_stroke_path(fz_context *ctx, fz_device *dev, fz_path *path, fz_stroke_state *state, const fz_matrix *ctm, fz_colorspace *cs, float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = Path_from_fz_path(ctx, env, path);
	jobject jstate = StrokeState_from_fz_stroke_state(ctx, env, state);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	jfloatArray jcolor = jfloatArray_from_fz_color(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_stroke_path_mid, jpath, jstate, jctm, jcs, jcolor, alpha);
}

static void
fz_java_device_clip_path(fz_context *ctx, fz_device *dev, fz_path *path, const fz_rect *rect, int even_odd, const fz_matrix *ctm)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = Path_from_fz_path(ctx, env, path);
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_clip_path_mid, jpath, jrect, even_odd, jctm);
}

static void
fz_java_device_clip_stroke_path(fz_context *ctx, fz_device *dev, fz_path *path, const fz_rect *rect, fz_stroke_state *state, const fz_matrix *ctm)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = Path_from_fz_path(ctx, env, path);
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);
	jobject jstate = StrokeState_from_fz_stroke_state(ctx, env, state);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_clip_stroke_path_mid, jpath, jrect, jstate, jctm);
}

static void
fz_java_device_fill_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm, fz_colorspace *cs, float *color, float alpha)
{
	LOGI("fz_java_device_fill_text");
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = Text_from_fz_text(ctx, env, text);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jfloatArray jcolor = jfloatArray_from_fz_color(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_fill_text_mid, jtext, jctm, jcs, jcolor, alpha);
}

static void
fz_java_device_stroke_text(fz_context *ctx, fz_device *dev, fz_text *text, fz_stroke_state *state, const fz_matrix *ctm, fz_colorspace *cs, float *color, float alpha)
{
	LOGI("fz_java_device_stroke_text");
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = Text_from_fz_text(ctx, env, text);
	jobject jstate = StrokeState_from_fz_stroke_state(ctx, env, state);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jfloatArray jcolor = jfloatArray_from_fz_color(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_stroke_text_mid, jtext, jstate, jctm, jcs, jcolor, alpha);
}

static void
fz_java_device_clip_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm)
{
	LOGI("fz_java_device_clip_text");
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = Text_from_fz_text(ctx, env, text);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_clip_text_mid, jtext, jctm);
}

static void
fz_java_device_clip_stroke_text(fz_context *ctx, fz_device *dev, fz_text *text, fz_stroke_state *state, const fz_matrix *ctm)
{
	LOGI("fz_java_device_clip_stroke_text");
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = Text_from_fz_text(ctx, env, text);
	jobject jstate = StrokeState_from_fz_stroke_state(ctx, env, state);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_clip_stroke_text_mid, jtext, jstate, jctm);
}

static void
fz_java_device_ignore_text(fz_context *ctx, fz_device *dev, fz_text *text, const fz_matrix *ctm)
{
	LOGI("fz_java_device_ignore_text");
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = Text_from_fz_text(ctx, env, text);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_ignore_text_mid, jtext, jctm);
}

static void
fz_java_device_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shd, const fz_matrix *ctm, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jshd = Shade_from_fz_shade(ctx, env, shd);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_fill_shade_mid, jshd, jctm, alpha);
}

static void
fz_java_device_fill_image(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = Image_from_fz_image(ctx, env, img);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_fill_image_mid, jimg, jctm, alpha);
}

static void
fz_java_device_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, fz_colorspace *cs, float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = Image_from_fz_image(ctx, env, img);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jfloatArray jcolor = jfloatArray_from_fz_color(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_fill_image_mask_mid, jimg, jctm, jcs, jcolor, alpha);
}

static void
fz_java_device_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *img, const fz_rect *rect, const fz_matrix *ctm)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = Image_from_fz_image(ctx, env, img);
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, device_clip_image_mask_mid, jimg, jrect, jctm);
}

static void
fz_java_device_pop_clip(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, device_pop_clip_mid);
}

static void
fz_java_device_begin_mask(fz_context *ctx, fz_device *dev, const fz_rect *rect, int luminosity, fz_colorspace *cs, float *bc)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);
	jobject jcs = ColorSpace_from_fz_colorspace(ctx, env, cs);
	jfloatArray jbc = jfloatArray_from_fz_color(ctx, env, bc, cs ? cs->n :	FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, device_begin_mask_mid, jrect, luminosity, jcs, jbc);
}

static void
fz_java_device_end_mask(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, device_end_mask_mid);
}

static void
fz_java_device_begin_group(fz_context *ctx, fz_device *dev, const fz_rect *rect, int isolated, int knockout, int blendmode, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jrect = Rect_from_fz_rect(ctx, env, rect);

	(*env)->CallVoidMethod(env, jdev->self, device_begin_group_mid, jrect, isolated, knockout, blendmode, alpha);
}

static void
fz_java_device_end_group(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, device_end_group_mid);
}

static int
fz_java_device_begin_tile(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jarea = Rect_from_fz_rect(ctx, env, area);
	jobject jview = Rect_from_fz_rect(ctx, env, view);
	jobject jctm = Matrix_from_fz_matrix(ctx, env, ctm);
	int res;

	res = (*env)->CallIntMethod(env, jdev->self, device_begin_tile_mid, jarea, jview, xstep, ystep, jctm, id);

	return res;
}

static void
fz_java_device_end_tile(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, device_end_tile_mid);
}

static void
fz_java_device_drop_imp(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;

	/* Nothing to do, currently */
	jdev = jdev;
}

static fz_device *fz_new_java_device(JNIEnv *env, jobject self, fz_context *ctx)
{
	fz_device *dev = NULL;
	fz_java_device *jdev = NULL;

	fz_var(dev);
	fz_var(jdev);

	fz_try(ctx)
	{
		jdev = fz_new_device(ctx, sizeof(fz_java_device));
		dev = &jdev->base;
		jdev->env = env;
		jdev->self = self;
		dev->drop_imp = fz_java_device_drop_imp;

		dev->fill_path = fz_java_device_fill_path;
		dev->stroke_path = fz_java_device_stroke_path;
		dev->clip_path = fz_java_device_clip_path;
		dev->clip_stroke_path = fz_java_device_clip_stroke_path;

		dev->fill_text = fz_java_device_fill_text;
		dev->stroke_text = fz_java_device_stroke_text;
		dev->clip_text = fz_java_device_clip_text;
		dev->clip_stroke_text = fz_java_device_clip_stroke_text;

		dev->fill_shade = fz_java_device_fill_shade;
		dev->fill_image = fz_java_device_fill_image;
		dev->fill_image_mask = fz_java_device_fill_image_mask;
		dev->clip_image_mask = fz_java_device_clip_image_mask;

		dev->pop_clip = fz_java_device_pop_clip;

		dev->begin_mask = fz_java_device_begin_mask;
		dev->end_mask = fz_java_device_end_mask;
		dev->begin_group = fz_java_device_begin_group;
		dev->end_group = fz_java_device_end_group;

		dev->begin_tile = fz_java_device_begin_tile;
		dev->end_tile = fz_java_device_end_tile;
	}
	fz_catch(ctx)
	{
		jclass exClass;

		fz_free(ctx, jdev);
		throwOutOfMemoryError(env, "Failed to create fz_java_device");
		dev = NULL;
	}
	return dev;
}

/* Conversion functions: Java to C */
static inline fz_colorspace *fz_colorspace_from_ColorSpace(JNIEnv *env, jobject jobj)
{
	return CAST(fz_colorspace *, (*env)->GetLongField(env, jobj, colorspace_fid));
}


static fz_device *fz_device_from_Device(JNIEnv *env, jobject self, fz_context *ctx)
{
	fz_device *dev = CAST(fz_device *, (*env)->GetLongField(env, self, device_fid));

	if (dev == NULL)
	{
		/* This must be a Java device. Create a native shim. */
		dev = fz_new_java_device(env, self, ctx);
		(*env)->SetLongField(env, self, device_fid, jlong_cast(dev));
	}
	return dev;
}

static inline fz_image *fz_image_from_Image(JNIEnv *env, jobject jobj)
{
	return CAST(fz_image *, (*env)->GetLongField(env, jobj, image_fid));
}

static inline fz_matrix fz_matrix_from_Matrix(JNIEnv *env, jobject jmat)
{
	fz_matrix mat;

	mat.a = (*env)->GetFloatField(env, jmat, matrix_a_fid);
	mat.b = (*env)->GetFloatField(env, jmat, matrix_b_fid);
	mat.c = (*env)->GetFloatField(env, jmat, matrix_c_fid);
	mat.d = (*env)->GetFloatField(env, jmat, matrix_d_fid);
	mat.e = (*env)->GetFloatField(env, jmat, matrix_e_fid);
	mat.f = (*env)->GetFloatField(env, jmat, matrix_f_fid);

	return mat;
}

static inline fz_path *fz_path_from_Path(JNIEnv *env, jobject jobj)
{
	return CAST(fz_path *, (*env)->GetLongField(env, jobj, path_fid));
}

static inline fz_rect fz_rect_from_Rect(JNIEnv *env, jobject jrect)
{
	fz_rect rect;

	rect.x0 = (*env)->GetFloatField(env, jrect, rect_x0_fid);
	rect.x1 = (*env)->GetFloatField(env, jrect, rect_x1_fid);
	rect.y0 = (*env)->GetFloatField(env, jrect, rect_y0_fid);
	rect.y1 = (*env)->GetFloatField(env, jrect, rect_y1_fid);

	return rect;
}

static inline fz_shade *fz_shade_from_Shade(JNIEnv *env, jobject jobj)
{
	return CAST(fz_shade *, (*env)->GetLongField(env, jobj, shade_fid));
}

static inline fz_stroke_state *fz_stroke_state_from_StrokeState(JNIEnv *env, jobject jobj)
{
	return CAST(fz_stroke_state *, (*env)->GetLongField(env, jobj, stroke_fid));
}

static inline fz_text *fz_text_from_Text(JNIEnv *env, jobject jobj)
{
	return CAST(fz_text *, (*env)->GetLongField(env, jobj, text_fid));
}

static inline fz_font *fz_font_from_Font(JNIEnv *env, jobject jobj)
{
	return CAST(fz_font *, (*env)->GetLongField(env, jobj, font_fid));
}

static inline void fz_color_from_jfloatArray(JNIEnv *env, float *color, int n, jfloatArray jcolor)
{
	jsize len = (*env)->GetArrayLength(env, jcolor);
	if (len > n)
		len = n;
	(*env)->GetFloatArrayRegion(env, jcolor, 0, len, color);
	if (len < n)
		memset(color+len, 0, (n-len)*sizeof(float));
}

static inline fz_cookie *fz_cookie_from_Cookie(JNIEnv *env, jobject jobj)
{
	return CAST(fz_cookie *, (*env)->GetLongField(env, jobj, cookie_fid));
}

static inline fz_display_list *fz_display_list_from_DisplayList(JNIEnv *env, jobject jobj)
{
	return CAST(fz_display_list *, (*env)->GetLongField(env, jobj, displaylist_fid));
}

static inline fz_page *fz_page_from_Page(JNIEnv *env, jobject jobj)
{
	return CAST(fz_page *, (*env)->GetLongField(env, jobj, page_fid));
}

static inline fz_document *fz_document_from_Document(JNIEnv *env, jobject jobj)
{
	jlong l;

	l = (*env)->GetLongField(env, jobj, document_fid);
	return CAST(fz_document *, l);
}

static inline fz_annot *fz_annot_from_Annotation(JNIEnv *env, jobject jobj)
{
	return CAST(fz_annot *, (*env)->GetLongField(env, jobj, annot_fid));
}

static inline fz_outline *fz_outline_from_Outline(JNIEnv *env, jobject jobj)
{
	return CAST(fz_outline *, (*env)->GetLongField(env, jobj, outline_fid));
}

static inline fz_link *fz_link_from_Link(JNIEnv *env, jobject jobj)
{
	return CAST(fz_link *, (*env)->GetLongField(env, jobj, link_fid));
}

/* Helper function for exception handling */

static void jni_throw(JNIEnv *env, int type, const char *mess)
{
	const char *className;
	int len;
	jclass cla;

	switch(type)
	{
	case FZ_ERROR_TRYLATER:
		cla = trylaterexception_class;
		break;
	default:
	case FZ_ERROR_GENERIC:
		cla = exception_class;
		break;
	}

	(void)(*env)->ThrowNew(env, cla, mess);
}

static void jni_rethrow(JNIEnv *env, fz_context *ctx)
{
	jni_throw(env, fz_caught(ctx), fz_caught_message(ctx));
}

/* ColorSpace Interface */

JNIEXPORT void JNICALL
JNI_FN(ColorSpace_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, self);

	if (ctx == NULL || cs == NULL)
		return;

	fz_drop_colorspace(ctx, cs);
}

JNIEXPORT void JNICALL
JNI_FN(ColorSpace_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(ColorSpace_finalize)(env, self);

	(*env)->SetLongField(env, self, colorspace_fid, 0);
}

JNIEXPORT int JNICALL
JNI_FN(ColorSpace_getNumComponents)(JNIEnv * env, jobject self)
{
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, self);

	if (cs == NULL)
		return 0;

	return cs->n;
}

JNIEXPORT jlong JNICALL
JNI_FN(ColorSpace_newDeviceRGB)(JNIEnv * env, jobject self, jlong size)
{
	fz_context *ctx = get_context(env);

	return jlong_cast(fz_device_rgb(ctx));
}

JNIEXPORT jlong JNICALL
JNI_FN(ColorSpace_newDeviceGray)(JNIEnv * env, jobject self, jlong size)
{
	fz_context *ctx = get_context(env);

	return jlong_cast(fz_device_gray(ctx));
}

JNIEXPORT jlong JNICALL
JNI_FN(ColorSpace_newDeviceCMYK)(JNIEnv * env, jobject self, jlong size)
{
	fz_context *ctx = get_context(env);

	return jlong_cast(fz_device_cmyk(ctx));
}

/* Device Interface */

typedef struct CDeviceNativeInfo CDeviceNativeInfo;

typedef void (CDeviceLockFn)(JNIEnv *env, CDeviceNativeInfo *info);
typedef void (CDeviceUnlockFn)(JNIEnv *env, CDeviceNativeInfo *info);

struct CDeviceNativeInfo
{
	/* Some devices (like the AndroidDrawDevice, or AwtDrawDevice) need
	 * to lock/unlock the java object around device calls. We have functions
	 * here to do that. Other devices (like the DisplayList device) need
	 * no such locking, so these are NULL. */
	CDeviceLockFn *lock; /* Function to lock */
	CDeviceUnlockFn *unlock; /* Function to unlock */
	jobject object; /* The java object that needs to be locked. */

	/* Conceptually, we support drawing onto a 'plane' of pixels.
	 * The plane is width/height in size. The page is positioned on this
	 * at pageX0,pageY0 -> pageX1,PageY1. We want to redraw the given patch
	 * of this.
	 *
	 * The samples pointer in pixmap is updated on every lock/unlock, to
	 * cope with the object moving in memory.
	 */
	fz_pixmap *pixmap;
	int pageX0;
	int pageY0;
	int width;
};

static CDeviceNativeInfo *lockCDevice(JNIEnv *env, jobject self)
{
	CDeviceNativeInfo *info;

	info = CAST(CDeviceNativeInfo *, (*env)->GetLongField(env, self, cdevice_nativeinfo_fid));
	if (info == NULL)
	{
		/* Some devices (like the Displaylist device) need no locking,
		 * so have no info. */
		return NULL;
	}
	info->object = (*env)->GetObjectField(env, self, cdevice_nativeresource_fid);

	info->lock(env, info);

	return info;
}

static void unlockCDevice(JNIEnv *env, CDeviceNativeInfo *info)
{
	if (info != NULL)
		info->unlock(env, info);
}

JNIEXPORT void JNICALL
JNI_FN(Device_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);

	if (ctx == NULL || dev == NULL)
		return;

	fz_drop_device(ctx, dev);
}

JNIEXPORT void JNICALL
JNI_FN(Device_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Device_finalize)(env, self);

	(*env)->SetLongField(env, self, device_fid, 0);
}


JNIEXPORT void JNICALL
JNI_FN(CDevice_beginPage)(JNIEnv *env, jobject self, jobject jrect, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_begin_page(ctx, dev, &rect, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_endPage)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_end_page(ctx, dev);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_fillPath)(JNIEnv *env, jobject self, jobject jpath, int even_odd, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_path *path = fz_path_from_Path(env, jpath);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_fill_path(ctx, dev, path, even_odd, &ctm, cs, color, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_strokePath)(JNIEnv *env, jobject self, jobject jpath, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_path *path = fz_path_from_Path(env, jpath);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_stroke_path(ctx, dev, path, stroke, &ctm, cs, color, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_clipPath)(JNIEnv *env, jobject self, jobject jpath, jobject jrect, int even_odd, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_path *path = fz_path_from_Path(env, jpath);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_clip_path(ctx, dev, path, &rect, even_odd, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_clipStrokePath)(JNIEnv *env, jobject self, jobject jpath, jobject jrect, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_path *path = fz_path_from_Path(env, jpath);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_clip_stroke_path(ctx, dev, path, &rect, stroke, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_fillText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_text *text = fz_text_from_Text(env, jtext);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_fill_text(ctx, dev, text, &ctm, cs, color, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_strokeText)(JNIEnv *env, jobject self, jobject jtext, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_text *text = fz_text_from_Text(env, jtext);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_stroke_text(ctx, dev, text, stroke, &ctm, cs, color, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_clipText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_text *text = fz_text_from_Text(env, jtext);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_clip_text(ctx, dev, text, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_clipStrokeText)(JNIEnv *env, jobject self, jobject jtext, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_text *text = fz_text_from_Text(env, jtext);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_clip_stroke_text(ctx, dev, text, stroke, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_ignoreText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_text *text = fz_text_from_Text(env, jtext);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_ignore_text(ctx, dev, text, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_fillShade)(JNIEnv *env, jobject self, jobject jshade, jobject jctm, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_shade *shade = fz_shade_from_Shade(env, jshade);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_fill_shade(ctx, dev, shade, &ctm, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_fillImage)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_image *image = fz_image_from_Image(env, jimg);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_fill_image(ctx, dev, image, &ctm, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_fillImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_image *image = fz_image_from_Image(env, jimg);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_fill_image_mask(ctx, dev, image, &ctm, cs, color, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_clipImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jrect, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_image *image = fz_image_from_Image(env, jimg);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_clip_image_mask(ctx, dev, image, &rect, &ctm);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_popClip)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_pop_clip(ctx, dev);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_beginMask)(JNIEnv *env, jobject self, jobject jrect, int luminosity, jobject jcs, jfloatArray jcolor)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	fz_colorspace *cs = fz_colorspace_from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_color_from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

		fz_begin_mask(ctx, dev, &rect, luminosity, cs, color);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_endMask)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_end_mask(ctx, dev);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_beginGroup)(JNIEnv *env, jobject self, jobject jrect, int isolated, int knockout, int blendmode, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_rect rect = fz_rect_from_Rect(env, jrect);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_begin_group(ctx, dev, &rect, isolated, knockout, blendmode, alpha);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_endGroup)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_end_group(ctx, dev);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT int JNICALL
JNI_FN(CDevice_beginTile)(JNIEnv *env, jobject self, jobject jarea, jobject jview, float xstep, float ystep, jobject jctm, int id)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_rect area = fz_rect_from_Rect(env, jarea);
	fz_rect view = fz_rect_from_Rect(env, jview);
	int i;
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		i = fz_begin_tile_id(ctx, dev, &area, &view, xstep, ystep, &ctm, id);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}

	return i;
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_endTile)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = fz_device_from_Device(env, self, ctx);
	CDeviceNativeInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockCDevice(env, self);

	fz_try(ctx)
	{
		fz_end_tile(ctx, dev);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

/* Draw Device interface */
static jlong
newCDevice(JNIEnv *env, jobject self, fz_context *ctx, jobject obj, jint width, jint height, CDeviceLockFn *lock, CDeviceUnlockFn *unlock, int pageX0, int pageY0, int pageX1, int pageY1, int patchX0, int patchY0, int patchX1, int patchY1)
{
	fz_device *device = NULL;
	fz_pixmap *pixmap = NULL;
	int ret;
	unsigned char dummy;
	CDeviceNativeInfo *ninfo = NULL;
	fz_irect clip, pixbbox;

	if (ctx == NULL)
		return 0;

	fz_var(pixmap);
	fz_var(ninfo);

	fz_try(ctx)
	{
		//LOGI("DrawDeviceNative: bitmap=%d,%d page=%d,%d->%d,%d patch=%d,%d->%d,%d", width, height, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
		/* Sanitise patch w.r.t page. */
		if (patchX0 < pageX0)
			patchX0 = pageX0;
		if (patchY0 < pageY0)
			patchY0 = pageY0;
		if (patchX1 > pageX1)
			patchX1 = pageX1;
		if (patchY1 > pageY1)
			patchY1 = pageY1;

		clip.x0 = patchX0;
		clip.y0 = patchY0;
		clip.x1 = patchX1;
		clip.y1 = patchY1;

		/* Check for sanity. */
		//LOGI("clip = %d,%d->%d,%d", clip.x0, clip.y0, clip.x1, clip.y1);
		if (clip.x0 < 0 || clip.y0 < 0 || clip.x1 > width || clip.y1 > height)
			fz_throw(ctx, FZ_ERROR_GENERIC, "patch would draw out of bounds!");

		clip.x0 -= pageX0;
		clip.y0 -= pageY0;
		clip.x1 -= pageX0;
		clip.y1 -= pageY0;

		/* pixmaps cannot handle right-edge padding, so the bbox must be expanded to
		 * match the pixels data */
		pixbbox = clip;
		pixbbox.x1 = pixbbox.x0 + width;
		pixmap = fz_new_pixmap_with_bbox_and_data(ctx, fz_device_rgb(ctx), &pixbbox, &dummy);
		ninfo = fz_malloc(ctx, sizeof(*ninfo));
		ninfo->pixmap = pixmap;
		ninfo->lock = lock;
		ninfo->unlock = unlock;
		ninfo->pageX0 = pageX0;
		ninfo->pageY0 = pageY0;
		ninfo->width = width;
		ninfo->object = obj;
		(*env)->SetLongField(env, self, cdevice_nativeinfo_fid, jlong_cast(ninfo));
		(*env)->SetObjectField(env, self, cdevice_nativeresource_fid, obj);
		lockCDevice(env,self);
		fz_clear_pixmap_rect_with_value(ctx, pixmap, 0xff, &clip);
		unlockCDevice(env,ninfo);
		device = fz_new_draw_device_with_bbox(ctx, pixmap, &clip);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pixmap);
		fz_free(ctx, ninfo);
		jni_rethrow(env, ctx);
	}
	return jlong_cast(device);
}

static void androidDrawDevice_lock(JNIEnv *env, CDeviceNativeInfo *info)
{
	uint8_t *pixels;

	assert(info != NULL);
	assert(info->object != NULL);

	if (AndroidBitmap_lockPixels(env, info->object, (void **)&pixels) < 0)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Bitmap lock failed in DrawDevice call");
		return;
	}

	/* Now offset pixels to allow for the page offsets */
	//pixels += sizeof(int32_t) * (info->pageX0 + info->width * info->pageY0);

	info->pixmap->samples = pixels;
}

static void androidDrawDevice_unlock(JNIEnv *env, CDeviceNativeInfo *info)
{
	assert(info != NULL);
	assert(info->object != NULL);

	if (AndroidBitmap_unlockPixels(env, info->object) < 0)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Bitmap unlock failed in DrawDevice call");
	}
}

JNIEXPORT jlong JNICALL
JNI_FN(AndroidDrawDevice_newNative)(JNIEnv *env, jobject self, jobject jbitmap, int pageX0, int pageY0, int pageX1, int pageY1, int patchX0, int patchY0, int patchX1, int patchY1)
{
	fz_context *ctx = get_context(env);
	AndroidBitmapInfo info;
	jlong device = 0;
	int ret;

	fz_try(ctx)
	{
		if ((ret = AndroidBitmap_getInfo(env, jbitmap, &info)) < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new DrawDevice failed to get bitmap info");

		if (info.format != ANDROID_BITMAP_FORMAT_RGBA_8888)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new DrawDevice failed as bitmap format is not RGBA_8888");

		if (info.stride != info.width*4)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new DrawDevice failed as bitmap width != stride");

		device = newCDevice(env, self, ctx, jbitmap, info.width, info.height, androidDrawDevice_lock, androidDrawDevice_unlock, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return device;
}

static void awtDrawDevice_lock(JNIEnv *env, CDeviceNativeInfo *info)
{
	int8_t *pixels;

	assert(info != NULL);
	assert(info->object != NULL);
	assert(info->pixmap != NULL);

	//pixels = (unsigned char *)((*env)->GetIntArrayElements(env, info->object, 0));

	/* Now offset pixels to allow for the page offsets */
	pixels += sizeof(int32_t) * (info->pageX0 + info->width * info->pageY0);

	info->pixmap->samples = pixels;
}

static void awtDrawDevice_unlock(JNIEnv *env, CDeviceNativeInfo *info)
{
	int8_t *pixels = info->pixmap->samples;

	assert(info != NULL);
	assert(info->object != NULL);
	assert(info->pixmap != NULL);

	/* Now offset pixels to allow for the page offsets */
	//pixels -= sizeof(int32_t) * (info->pageX0 + info->width * info->pageY0);

	(*env)->ReleaseIntArrayElements(env, info->object, (int *)(void *)pixels, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(AwtDrawDevice_newNative)(JNIEnv *env, jobject self, jobject rgba, jint w, jint h, int pageX0, int pageY0, int pageX1, int pageY1, int patchX0, int patchY0, int patchX1, int patchY1)
{
	fz_context *ctx = get_context(env);

	return newCDevice(env, self, ctx, rgba, w, h, awtDrawDevice_lock, awtDrawDevice_unlock, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	CDeviceNativeInfo *ninfo;

	ninfo = CAST(CDeviceNativeInfo *, (*env)->GetLongField(env, self, cdevice_nativeinfo_fid));
	if (ninfo != NULL)
	{
		fz_drop_pixmap(ctx, ninfo->pixmap);
		fz_free(ctx, ninfo);
	}
	(*env)->SetLongField(env, self, cdevice_nativeinfo_fid, 0);
}

JNIEXPORT void JNICALL
JNI_FN(CDevice_destroy)(JNIEnv *env, jobject self)
{
	JNI_FN(CDevice_finalize)(env, self);
	JNI_FN(Device_finalize)(env, self); /* Super class destroy */
}

/* Path Interface */

JNIEXPORT void JNICALL
JNI_FN(Path_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_drop_path(ctx, path);
}

JNIEXPORT void JNICALL
JNI_FN(Path_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Path_finalize)(env, self);

	(*env)->SetLongField(env, self, path_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(Path_newNative)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
	{
		path = fz_new_path(ctx);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(path);
}

JNIEXPORT jobject JNICALL
JNI_FN(Path_currentPoint)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);
	fz_point point;
	jmethodID cons;
	jobject jpoint;

	if (ctx == NULL || path == NULL)
		return NULL;

	fz_try(ctx)
	{
		point = fz_currentpoint(ctx, path);
		jpoint = Point_from_fz_point(ctx, env, point);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jpoint;
}

JNIEXPORT void JNICALL
JNI_FN(Path_moveTo)(JNIEnv * env, jobject self, float x, float y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_moveto(ctx, path, x, y);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_lineTo)(JNIEnv * env, jobject self, float x, float y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_lineto(ctx, path, x, y);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_curveTo)(JNIEnv * env, jobject self, float cx1, float cy1, float cx2, float cy2, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_curveto(ctx, path, cx1, cy1, cx2, cy2, ex, ey);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_curveToV)(JNIEnv * env, jobject self, float cx, float cy, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_curvetov(ctx, path, cx, cy, ex, ey);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_curveToY)(JNIEnv * env, jobject self, float cx, float cy, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_curvetoy(ctx, path, cx, cy, ex, ey);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_close)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_closepath(ctx, path);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Path_transform)(JNIEnv * env, jobject self, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
	{
		fz_transform_path(ctx, path, &ctm);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT jlong JNICALL
JNI_FN(Path_clone)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);
	fz_path *path2 = NULL;

	if (ctx == NULL || path == NULL)
		return 0;

	fz_try(ctx)
	{
		path2 = fz_clone_path(ctx, path);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(path2);
}

JNIEXPORT jobject JNICALL
JNI_FN(Path_bound)(JNIEnv * env, jobject self, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);
	jobject jrect;
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_rect rect;

	if (ctx == NULL || path == NULL)
		return NULL;

	fz_try(ctx)
	{
		fz_bound_path(ctx, path, stroke, &ctm, &rect);

		jrect = Rect_from_fz_rect(ctx, env, &rect);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jrect;
}

typedef struct {
	JNIEnv *env;
	jobject jproc;
} pproc_data;

static void
pathProcMoveTo(fz_context *ctx, void *arg, float x, float y)
{
	pproc_data *pproc = (pproc_data *)arg;

	(*pproc->env)->CallVoidMethod(pproc->env, pproc->jproc, pathproc_moveto_mid, x, y);
}

static void
pathProcLineTo(fz_context *ctx, void *arg, float x, float y)
{
	pproc_data *pproc = (pproc_data *)arg;

	(*pproc->env)->CallVoidMethod(pproc->env, pproc->jproc, pathproc_lineto_mid, x, y);
}

static void
pathProcCurveTo(fz_context *ctx, void *arg, float x1, float y1, float x2, float y2, float x3, float y3)
{
	pproc_data *pproc = (pproc_data *)arg;

	(*pproc->env)->CallVoidMethod(pproc->env, pproc->jproc, pathproc_curveto_mid, x1, y1, x2, y2, x3, y3);
}

static void
pathProcClose(fz_context *ctx, void *arg)
{
	pproc_data *pproc = (pproc_data *) arg;

	(*pproc->env)->CallVoidMethod(pproc->env, pproc->jproc, pathproc_close_mid);
}

static const fz_path_processor path_proc =
{
	pathProcMoveTo,
	pathProcLineTo,
	pathProcCurveTo,
	pathProcClose
};

void JNICALL
JNI_FN(Path_process)(JNIEnv * env, jobject self, jobject jproc)
{
	fz_context *ctx = get_context(env);
	fz_path *path = fz_path_from_Path(env, self);
	int i = 0, k = 0;
	int n;
	pproc_data data;

	if (path == NULL || jproc == NULL)
		return;

	data.env = env;
	data.jproc = jproc;

	fz_process_path(ctx, &path_proc, &data, path);
}


/* StrokeState interface */

JNIEXPORT void JNICALL
JNI_FN(StrokeState_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	if (ctx == NULL || stroke == NULL)
		return;

	fz_drop_stroke_state(ctx, stroke);
}

JNIEXPORT void JNICALL
JNI_FN(StrokeState_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(StrokeState_finalize)(env, self);

	(*env)->SetLongField(env, self, stroke_fid, 0);
}


JNIEXPORT jlong JNICALL
JNI_FN(Path_newStrokeState)(JNIEnv * env, jobject self, int startCap, int dashCap, int endCap, int lineJoin, float lineWidth, float miterLimit, float dashPhase, jfloatArray dash)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = NULL;
	jsize len = (*env)->GetArrayLength(env, dash);

	if (ctx == NULL)
		return 0;

	fz_var(stroke);

	fz_try(ctx)
	{
		stroke = fz_new_stroke_state_with_dash_len(ctx, len);
		stroke->start_cap = startCap;
		stroke->dash_cap = dashCap;
		stroke->end_cap = endCap;
		stroke->linejoin = lineJoin;
		stroke->linewidth = lineWidth;
		stroke->miterlimit = miterLimit;
		stroke->dash_phase = dashPhase;
		stroke->dash_len = len;
		(*env)->GetFloatArrayRegion(env, dash, 0, len, &stroke->dash_list[0]);
	}
	fz_catch(ctx)
	{
		fz_drop_stroke_state(ctx, stroke);
		jni_rethrow(env, ctx);
	}
	return jlong_cast(stroke);
}

JNIEXPORT int JNICALL
JNI_FN(StrokeState_getStartCap)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->start_cap : 0;
}

JNIEXPORT int JNICALL
JNI_FN(StrokeState_getDashCap)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->dash_cap : 0;
}

JNIEXPORT int JNICALL
JNI_FN(StrokeState_getEndCap)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->end_cap : 0;
}

JNIEXPORT int JNICALL
JNI_FN(StrokeState_getLineJoin)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->linejoin : 0;
}

JNIEXPORT float JNICALL
JNI_FN(StrokeState_getLineWidth)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->linewidth : 0;
}

JNIEXPORT float JNICALL
JNI_FN(StrokeState_getMiterLimit)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->miterlimit : 0;
}

JNIEXPORT float JNICALL
JNI_FN(StrokeState_getDashPhase)(JNIEnv * env, jobject self)
{
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);

	return stroke ? stroke->dash_phase : 0;
}

JNIEXPORT jfloatArray JNICALL
JNI_FN(StrokeState_getDashes)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, self);
	jfloatArray arr;

	if (stroke->dash_len == 0)
		return NULL;

	arr = (*env)->NewFloatArray(env, stroke->dash_len);
	if (arr == NULL)
		fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of floatArray failed");

	(*env)->SetFloatArrayRegion(env, arr, 0, stroke->dash_len, &stroke->dash_list[0]);

	return arr;
}

/* Text interface */

JNIEXPORT void JNICALL
JNI_FN(Text_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = fz_text_from_Text(env, self);

	if (ctx == NULL || text == NULL)
		return;

	fz_drop_text(ctx, text);
}

JNIEXPORT void JNICALL
JNI_FN(Text_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Text_finalize)(env, self);

	(*env)->SetLongField(env, self, text_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(Text_clone)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = fz_text_from_Text(env, self);
	fz_text *text2 = NULL;

	if (ctx == NULL || text == NULL)
		return 0;

	fz_try(ctx)
	{
		text2 = fz_clone_text(ctx, text);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(text2);
}

//JNIEXPORT jlong JNICALL
//JNI_FN(Text_newText)(JNIEnv * env, jobject self, jobject jfont, jobject jctm, int wmode)
//{
//	fz_context *ctx = get_context(env);
//	fz_text *text = NULL;
//	fz_font *font = fz_font_from_Font(env, jfont);
//	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
//
//	if (ctx == NULL)
//		return 0;
//
//	fz_try(ctx)
//	{
//		text = fz_new_text(ctx, font, &ctm, wmode);
//	}
//	fz_catch(ctx)
//	{
//		jni_rethrow(env, ctx);
//	}
//	return jlong_cast(text);
//}

JNIEXPORT jobject JNICALL
JNI_FN(Text_bound)(JNIEnv * env, jobject self, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_text *text = fz_text_from_Text(env, self);
	fz_stroke_state *stroke = fz_stroke_state_from_StrokeState(env, jstroke);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	jobject jrect;
	fz_rect rect;

	if (ctx == NULL || text == NULL)
		return NULL;

	fz_try(ctx)
	{
		fz_bound_text(ctx, text, stroke, &ctm, &rect);

		jrect = Rect_from_fz_rect(ctx, env, &rect);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jrect;
}

//JNIEXPORT void JNICALL
//JNI_FN(Text_add)(JNIEnv * env, jobject self, int gid, int ucs, float x, float y)
//{
//	fz_context *ctx = get_context(env);
//	fz_text *text = fz_text_from_Text(env, self);
//
//	if (ctx == NULL || text == NULL)
//		return;
//
//	fz_try(ctx)
//	{
//		fz_add_text(ctx, text, gid, ucs, x, y);
//	}
//	fz_catch(ctx)
//	{
//		jni_rethrow(env, ctx);
//	}
//}

/* Image interface */

JNIEXPORT void JNICALL
JNI_FN(Image_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *image = fz_image_from_Image(env, self);

	if (ctx == NULL || image == NULL)
		return;

	fz_drop_image(ctx, image);
}

JNIEXPORT void JNICALL
JNI_FN(Image_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Image_finalize)(env, self);

	(*env)->SetLongField(env, self, image_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(Image_newImageFromBitmap)(JNIEnv * env, jobject self, jobject jbitmap, jlong jmask)
{
	fz_context *ctx = get_context(env);
	fz_image *mask = CAST(fz_image *, jmask);
	fz_image *image = NULL;
	fz_pixmap *pixmap = NULL;
	AndroidBitmapInfo info;
	void *pixels;
	int ret;

	if (ctx == NULL)
		return 0;

	fz_var(pixmap);

	fz_try(ctx)
	{
		if (mask && mask->mask)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new Image failed as mask cannot be masked");

		if ((ret = AndroidBitmap_getInfo(env, jbitmap, &info)) < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new Image failed to get bitmap info");

		if (info.format != ANDROID_BITMAP_FORMAT_RGBA_8888)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new Image failed as bitmap format is not RGBA_8888");

		if (info.stride != info.width)
			fz_throw(ctx, FZ_ERROR_GENERIC, "new Image failed as bitmap width != stride");

		pixmap = fz_new_pixmap(ctx, fz_device_rgb(ctx), info.width, info.height);
		if (AndroidBitmap_lockPixels(env, jbitmap, &pixels) < 0)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Bitmap lock failed in new Image");
		memcpy(pixmap->samples, pixels, info.width * info.height * 4);
		(void)AndroidBitmap_unlockPixels(env, jbitmap);

		image = fz_new_image_from_pixmap(ctx, fz_keep_pixmap(ctx, pixmap), fz_keep_image(ctx, mask));
	}
	fz_always(ctx)
	{
		fz_drop_pixmap(ctx, pixmap);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(image);
}

JNIEXPORT int JNICALL
JNI_FN(Image_getWidth)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->w : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getHeight)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->h : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getNumComponents)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->n : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getBitsPerComponent)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->bpc : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getXResolution)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->xres : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getYResolution)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->yres : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getImageMask)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->imagemask : 0;
}

JNIEXPORT int JNICALL
JNI_FN(Image_getInterpolate)(JNIEnv * env, jobject self)
{
	fz_image *image = fz_image_from_Image(env, self);

	return image ? image->interpolate : 0;
}

JNIEXPORT jobject JNICALL
JNI_FN(Image_getMask)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *img = fz_image_from_Image(env, self);
	jobject jobj;

	if (img == NULL || img->mask == NULL)
		return NULL;

	jobj = Image_from_fz_image(ctx, env, img->mask);
	if (jobj != NULL)
		fz_keep_image(ctx, img->mask);

	return jobj;

died:
	fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of Image(Mask) failed");
	return NULL;
}

/* Outline interface */

JNIEXPORT void JNICALL
JNI_FN(Outline_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_outline *outline = fz_outline_from_Outline(env, self);

	if (ctx == NULL || outline == NULL)
		return;

	fz_drop_outline(ctx, outline);
}

JNIEXPORT void JNICALL
JNI_FN(Outline_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Outline_finalize)(env, self);

	(*env)->SetLongField(env, self, outline_fid, 0);
}

/* Annotation Interface */

JNIEXPORT void JNICALL
JNI_FN(Annotation_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = fz_annot_from_Annotation(env, self);

	if (ctx == NULL || link == NULL)
		return;

	fz_drop_annot(ctx, annot);
}

JNIEXPORT void JNICALL
JNI_FN(Annotation_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Annotation_finalize)(env, self);

	(*env)->SetLongField(env, self, annot_fid, 0);
}

JNIEXPORT void JNICALL
JNI_FN(Annotation_run)(JNIEnv * env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_cookie *cookie= fz_cookie_from_Cookie(env, jcookie);
	fz_device *dev = fz_device_from_Device(env, jdev, ctx);
	jobject jdoc;
	fz_annot *annot = fz_annot_from_Annotation(env, self);
	CDeviceNativeInfo *info;

	if (ctx == NULL || self == NULL || jdev == NULL)
		return;

	fz_var(dev);

	info = lockCDevice(env, jdev);

	fz_try(ctx)
	{
		fz_run_annot(ctx, annot, dev, &ctm, cookie);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT jlong JNICALL
JNI_FN(Annotation_advance)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot;

	if (ctx == NULL)
		return;

	fz_try(ctx)
	{
		annot = fz_annot_from_Annotation(env, self);

		annot = fz_next_annot(ctx, annot);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(annot);
}

/* Link interface */

JNIEXPORT void JNICALL
JNI_FN(Link_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_link *link = fz_link_from_Link(env, self);

	if (ctx == NULL || link == NULL)
		return;

	fz_drop_link(ctx, link);
}

JNIEXPORT void JNICALL
JNI_FN(Link_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Link_finalize)(env, self);

	(*env)->SetLongField(env, self, link_fid, 0);
}

/* Document interface */

JNIEXPORT void JNICALL
JNI_FN(Document_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = fz_document_from_Document(env, self);

	if (ctx == NULL || doc == NULL)
		return;

	fz_drop_document(ctx, doc);
}

JNIEXPORT void JNICALL
JNI_FN(Document_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Document_finalize)(env, self);

	(*env)->SetLongField(env, self, document_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(Document_newNative)(JNIEnv * env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	fz_document *document = NULL;
	const char *filename = NULL;

	if (ctx == NULL || jfilename == NULL)
		return 0;

	fz_var(filename);

	fz_try(ctx)
	{
		filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
		if (filename == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to convert filename");
		document = fz_open_document(ctx, filename);
	}
	fz_always(ctx)
	{
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}

	return jlong_cast(document);
}

JNIEXPORT int JNICALL
JNI_FN(Document_needsPassword)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	int ret;

	if (ctx == NULL || document == NULL)
		return 0;

	fz_try(ctx)
	{
		ret = fz_needs_password(ctx, document);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		ret = 0;
	}
	return ret;
}

JNIEXPORT int JNICALL
JNI_FN(Document_authenticatePassword)(JNIEnv * env, jobject self, jstring jpassword)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	int ret;
	const char *password = NULL;

	if (ctx == NULL || document == NULL)
		return 0;

	fz_var(password);

	fz_try(ctx)
	{
		if (jpassword == NULL)
			password = "";
		else
		{
			password = (*env)->GetStringUTFChars(env, jpassword, NULL);
			if (password == NULL)
				fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to convert password");
		}

		ret = fz_authenticate_password(ctx, document, password);
	}
	fz_always(ctx)
	{
		if (jpassword != NULL)
			(*env)->ReleaseStringUTFChars(env, jpassword, password);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		ret = 0;
	}
	return ret;
}

JNIEXPORT int JNICALL
JNI_FN(Document_countPages)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	int ret;

	if (ctx == NULL || document == NULL)
		return 0;

	fz_try(ctx)
	{
		ret = fz_count_pages(ctx, document);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		ret = 0;
	}
	return ret;
}

JNIEXPORT jobject JNICALL
JNI_FN(Document_getPage)(JNIEnv * env, jobject self, int n)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	fz_page *page = NULL;
	jobject jpage;

	if (ctx == NULL || document == NULL)
		return NULL;

	fz_var(page);

	fz_try(ctx)
	{
		page = fz_load_page(ctx, document, n);
		if (page == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getPage failed");

		jpage = Page_from_fz_page(ctx, env, page);
	}
	fz_catch(ctx)
	{
		fz_drop_page(ctx, page);
		jni_rethrow(env, ctx);
		jpage = NULL;
	}
	return jpage;
}

JNIEXPORT jobject JNICALL
JNI_FN(Document_getFileFormat)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	char info[64];

	if (ctx == NULL || document == NULL)
		return NULL;

	fz_lookup_metadata(ctx, document, FZ_META_FORMAT, info, sizeof(info));

	return (*env)->NewStringUTF(env, info);
}

JNIEXPORT jboolean JNICALL
JNI_FN(Document_isUnencryptedPDF)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	pdf_document *idoc = pdf_specifics(ctx, document);
	int cryptVer;

	if (idoc == NULL)
		return JNI_FALSE; // Not a PDF

	cryptVer = pdf_crypt_version(ctx, idoc);
	return (cryptVer == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
JNI_FN(Document_getOutline)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = fz_document_from_Document(env, self);
	fz_outline *outline = NULL;
	jobject joutline;

	if (ctx == NULL || document == NULL)
		return NULL;

	fz_var(outline);

	fz_try(ctx)
	{
		outline = fz_load_outline(ctx, document);
		if (outline == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getOutline failed");

		joutline = Outline_from_fz_outline(ctx, env, outline);
	}
	fz_catch(ctx)
	{
		fz_drop_outline(ctx, outline);
		jni_rethrow(env, ctx);
		joutline = NULL;
	}
	return joutline;
}

/* Page interface */

JNIEXPORT void JNICALL
JNI_FN(Page_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = fz_page_from_Page(env, self);

	if (ctx == NULL || page == NULL)
		return;

	fz_drop_page(ctx, page);
}

JNIEXPORT void JNICALL
JNI_FN(Page_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Page_finalize)(env, self);

	(*env)->SetLongField(env, self, page_fid, 0);
	(*env)->SetLongField(env, self, page_annots_fid, 0);
}

JNIEXPORT jobject JNICALL
JNI_FN(Page_bound)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = fz_page_from_Page(env, self);
	jobject jrect;
	fz_rect rect;

	if (ctx == NULL || page == NULL)
		return NULL;

	fz_try(ctx)
	{
		fz_bound_page(ctx, page, &rect);

		jrect = Rect_from_fz_rect(ctx, env, &rect);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jrect;
}

JNIEXPORT void JNICALL
JNI_FN(Page_run)(JNIEnv * env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_cookie *cookie = fz_cookie_from_Cookie(env, jcookie);
	fz_device *dev = fz_device_from_Device(env, jdev, ctx);
	fz_page *page = fz_page_from_Page(env, self);
	CDeviceNativeInfo *info;

	if (ctx == NULL || self == NULL || jdev == NULL)
		return;

	info = lockCDevice(env, jdev);

	fz_try(ctx)
	{
		fz_run_page(ctx, page, dev, &ctm, cookie);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(Page_runPageContents)(JNIEnv * env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_cookie *cookie = fz_cookie_from_Cookie(env, jcookie);
	fz_device *dev = fz_device_from_Device(env, jdev, ctx);
	fz_page *page = fz_page_from_Page(env, self);
	CDeviceNativeInfo *info;

	if (ctx == NULL)
		return;

	info = lockCDevice(env, jdev);

	fz_try(ctx)
	{
		fz_run_page_contents(ctx, page, dev, &ctm, cookie);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT jobject JNICALL
JNI_FN(Page_getAnnotations)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = fz_page_from_Page(env, self);
	jobject jrect;
	fz_rect rect;
	fz_annot *annot = NULL;
	fz_annot *first = NULL;
	jobject jannots = NULL;
	int ret;
	int annot_count;
	int i;

	if (ctx == NULL || page == NULL)
		return NULL;

	fz_var(annot);
	fz_var(jannots);

	fz_try(ctx)
	{
		jannots = (*env)->GetObjectField(env, self, page_annots_fid);

		first = fz_first_annot(ctx, page);

		/* Count the annotations */
		annot = first;
		for (annot_count = 0; annot != NULL; annot_count++)
			annot = fz_next_annot(ctx, annot);

		if (annot_count == 0)
		{
			/* If no annotations, we don't want an annotation
			 * object stored in the page. */
			if (jannots != NULL)
			{
				(*env)->SetObjectField(env, self, page_annots_fid, NULL);
			}
			break; /* No annotations! */
		}

		jannots = (*env)->NewObjectArray(env, annot_count, annot_class, NULL);
		if (jannots == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getAnnotations failed (1)");
		(*env)->SetObjectField(env, self, page_annots_fid, jannots);

		/* Now run through actually creating the annotation objects */
		annot = first;
		for (i = 0; annot != NULL && i < annot_count; i++)
		{
			jobject jannot = Annotation_from_fz_annot(ctx, env, annot);
			(*env)->SetObjectArrayElement(env, jannots, i, jannot);
			annot = fz_next_annot(ctx, annot);
		}
		if (annot != NULL || i != annot_count)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getAnnotations failed (4)");
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jannots;
}

/* private native final Link[] getLinks(jlong ctx); */


/* Cookie interface */

JNIEXPORT void JNICALL
JNI_FN(Cookie_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = fz_cookie_from_Cookie(env, self);

	if (ctx == NULL || cookie == NULL)
		return;

	fz_free(ctx, cookie);
}

JNIEXPORT void JNICALL
JNI_FN(Cookie_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(Cookie_finalize)(env, self);

	(*env)->SetLongField(env, self, cookie_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(Cookie_newNative)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);

	return jlong_cast(fz_malloc_struct(ctx, fz_cookie));
}

JNIEXPORT void JNICALL
JNI_FN(Cookie_abort)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = fz_cookie_from_Cookie(env, self);

	if (ctx == NULL || cookie == NULL)
		return;

	cookie->abort = 1;
}

/* DisplayList interface */
JNIEXPORT jlong JNICALL
JNI_FN(DisplayList_newNative)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);

	return jlong_cast(fz_new_display_list(ctx));
}

JNIEXPORT void JNICALL
JNI_FN(DisplayList_run)(JNIEnv * env, jobject self, jobject jdev, jobject jctm, jobject jrect, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = fz_display_list_from_DisplayList(env, self);
	fz_matrix ctm = fz_matrix_from_Matrix(env, jctm);
	fz_cookie *cookie = fz_cookie_from_Cookie(env, jcookie);
	fz_device *dev = fz_device_from_Device(env, jdev, ctx);
	CDeviceNativeInfo *info;
	fz_rect local_rect;
	fz_rect *rect;

	if (ctx == NULL || self == NULL || jdev == NULL || list == NULL)
		return;

	/* Use a scissor rectangle if one is supplied */
	if (jrect == NULL)
	{
		rect = NULL;
	}
	else
	{
		rect = &local_rect;
		local_rect = fz_rect_from_Rect(env, jrect);
	}

	info = lockCDevice(env, jdev);

	fz_try(ctx)
	{
		fz_run_display_list(ctx, list, dev, &ctm, rect, cookie);
	}
	fz_always(ctx)
	{
		unlockCDevice(env, info);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
}

JNIEXPORT void JNICALL
JNI_FN(DisplayList_finalize)(JNIEnv * env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = fz_display_list_from_DisplayList(env, self);

	if (ctx == NULL || list == NULL)
		return;

	fz_drop_display_list(ctx, list);
}

JNIEXPORT void JNICALL
JNI_FN(DisplayList_destroy)(JNIEnv * env, jobject self)
{
	JNI_FN(DisplayList_finalize)(env, self);

	(*env)->SetLongField(env, self, displaylist_fid, 0);
}

JNIEXPORT jlong JNICALL
JNI_FN(DisplayListDevice_newNative)(JNIEnv *env, jobject self, jobject jlist)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = fz_display_list_from_DisplayList(env, jlist);
	fz_device *device = NULL;
	int ret;
	unsigned char dummy;

	if (ctx == NULL || list == NULL)
		return 0;

	fz_try(ctx)
	{
		device = fz_new_list_device(ctx, list);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return jlong_cast(device);
}
