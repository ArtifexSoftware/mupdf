#include <jni.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <pthread.h>
#endif

#ifdef NDK_PROFILER
#include "prof.h"
#endif

#include "mupdf/fitz.h"
#include "mupdf/pdf.h"

#include "mupdf_native.h" /* javah generated prototypes */

#ifdef HAVE_ANDROID
#include <android/log.h>
#include <android/bitmap.h>
#define LOG_TAG "libmupdf"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,LOG_TAG,__VA_ARGS__)
#define LOGT(...) __android_log_print(ANDROID_LOG_INFO,"alert",__VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,LOG_TAG,__VA_ARGS__)
#else
#undef LOGI
#undef LOGE
#define LOGI(...) do{printf(__VA_ARGS__);putchar('\n');}while(0)
#define LOGE(...) do{printf(__VA_ARGS__);putchar('\n');}while(0)
#endif

#define MY_JNI_VERSION JNI_VERSION_1_6

#define FUN(A) Java_com_artifex_mupdf_fitz_ ## A
#define PKG "com/artifex/mupdf/fitz/"

/* Do our best to avoid type casting warnings. */

#define CAST(type, var) (type)pointer_cast(var)

static inline void *pointer_cast(jlong l)
{
	return (void *)(intptr_t)l;
}

static inline jlong jlong_cast(const void *p)
{
	return (jlong)(intptr_t)p;
}

/* All the cached classes/mids/fids we need. */

static jclass cls_Annot;
static jclass cls_ColorSpace;
static jclass cls_Cookie;
static jclass cls_Device;
static jclass cls_DisplayList;
static jclass cls_Document;
static jclass cls_Exception;
static jclass cls_Font;
static jclass cls_Image;
static jclass cls_Link;
static jclass cls_Matrix;
static jclass cls_NativeDevice;
static jclass cls_Object;
static jclass cls_OutOfMemoryError;
static jclass cls_Outline;
static jclass cls_Page;
static jclass cls_Path;
static jclass cls_PathWalker;
static jclass cls_Pixmap;
static jclass cls_Point;
static jclass cls_Rect;
static jclass cls_Shade;
static jclass cls_StrokeState;
static jclass cls_Text;
static jclass cls_TextWalker;
static jclass cls_TryLaterException;

static jfieldID fid_Annot_pointer;
static jfieldID fid_ColorSpace_pointer;
static jfieldID fid_Cookie_pointer;
static jfieldID fid_Device_pointer;
static jfieldID fid_DisplayList_pointer;
static jfieldID fid_Document_pointer;
static jfieldID fid_Font_pointer;
static jfieldID fid_Image_pointer;
static jfieldID fid_Link_pointer;
static jfieldID fid_Matrix_a;
static jfieldID fid_Matrix_b;
static jfieldID fid_Matrix_c;
static jfieldID fid_Matrix_d;
static jfieldID fid_Matrix_e;
static jfieldID fid_Matrix_f;
static jfieldID fid_NativeDevice_nativeInfo;
static jfieldID fid_NativeDevice_nativeResource;
static jfieldID fid_Outline_pointer;
static jfieldID fid_Page_nativeAnnots;
static jfieldID fid_Page_pointer;
static jfieldID fid_Path_pointer;
static jfieldID fid_Pixmap_pointer;
static jfieldID fid_Rect_x0;
static jfieldID fid_Rect_x1;
static jfieldID fid_Rect_y0;
static jfieldID fid_Rect_y1;
static jfieldID fid_Shade_pointer;
static jfieldID fid_StrokeState_pointer;
static jfieldID fid_Text_pointer;

static jmethodID mid_Annot_init;
static jmethodID mid_ColorSpace_fromPointer;
static jmethodID mid_ColorSpace_init;
static jmethodID mid_Device_beginGroup;
static jmethodID mid_Device_beginMask;
static jmethodID mid_Device_beginTile;
static jmethodID mid_Device_clipImageMask;
static jmethodID mid_Device_clipPath;
static jmethodID mid_Device_clipStrokePath;
static jmethodID mid_Device_clipStrokeText;
static jmethodID mid_Device_clipText;
static jmethodID mid_Device_endGroup;
static jmethodID mid_Device_endMask;
static jmethodID mid_Device_endTile;
static jmethodID mid_Device_fillImage;
static jmethodID mid_Device_fillImageMask;
static jmethodID mid_Device_fillPath;
static jmethodID mid_Device_fillShade;
static jmethodID mid_Device_fillText;
static jmethodID mid_Device_ignoreText;
static jmethodID mid_Device_popClip;
static jmethodID mid_Device_strokePath;
static jmethodID mid_Device_strokeText;
static jmethodID mid_Font_init;
static jmethodID mid_Image_init;
static jmethodID mid_Matrix_init;
static jmethodID mid_Object_toString;
static jmethodID mid_Outline_init;
static jmethodID mid_Page_init;
static jmethodID mid_PathWalker_closePath;
static jmethodID mid_PathWalker_curveTo;
static jmethodID mid_PathWalker_lineTo;
static jmethodID mid_PathWalker_moveTo;
static jmethodID mid_Path_init;
static jmethodID mid_Pixmap_init;
static jmethodID mid_Point_init;
static jmethodID mid_Rect_init;
static jmethodID mid_Shade_init;
static jmethodID mid_StrokeState_init;
static jmethodID mid_Text_init;
static jmethodID mid_TextWalker_showGlyph;

#ifdef _WIN32
static DWORD context_key;
#else
static pthread_key_t context_key;
#endif
static fz_context *base_context;

/* Helper functions to set the java exception flag. */

static void jni_throw(JNIEnv *env, int type, const char *mess)
{
	if (type == FZ_ERROR_TRYLATER)
		(*env)->ThrowNew(env, cls_TryLaterException, mess);
	else
		(*env)->ThrowNew(env, cls_Exception, mess);
}

static void jni_throw_oom(JNIEnv *env, const char *info)
{
	(*env)->ThrowNew(env, cls_OutOfMemoryError, info);
}

static void jni_rethrow(JNIEnv *env, fz_context *ctx)
{
	jni_throw(env, fz_caught(ctx), fz_caught_message(ctx));
}

/* Convert a java exception and throw into fitz. */

static void fz_throw_java(fz_context *ctx, JNIEnv *env)
{
	jthrowable ex = (*env)->ExceptionOccurred(env);
	if (ex)
	{
		jobject msg = (*env)->CallObjectMethod(env, ex, mid_Object_toString);
		if (msg)
		{
			const char *p = (*env)->GetStringUTFChars(env, msg, NULL);
			if (p)
			{
				char buf[256];
				fz_strlcpy(buf, p, sizeof buf);
				(*env)->ReleaseStringUTFChars(env, msg, p);
				fz_throw(ctx, FZ_ERROR_GENERIC, "%s", buf);
			}
		}
	}
	fz_throw(ctx, FZ_ERROR_GENERIC, "unknown java error");
}

/* Load classes, field and method IDs. */

static const char *current_class_name = NULL;
static jclass current_class = NULL;

static jclass get_class(int *failed, JNIEnv *env, const char *name)
{
	jclass local;

	if (*failed)
		return NULL;

	current_class_name = name;
	local = (*env)->FindClass(env, name);
	if (local == NULL)
	{
		LOGI("Failed to find class %s", name);
		*failed = 1;
		return NULL;
	}

	current_class = (*env)->NewGlobalRef(env, local);
	if (current_class == NULL)
	{
		LOGI("Failed to make global ref for %s", name);
		*failed = 1;
		return NULL;
	}

	(*env)->DeleteLocalRef(env, local);

	return current_class;
}

static jfieldID get_field(int *failed, JNIEnv *env, const char *field, const char *sig)
{
	jfieldID fid;

	if (*failed || current_class == NULL)
		return NULL;

	fid = (*env)->GetFieldID(env, current_class, field, sig);
	if (fid == 0)
	{
		LOGI("Failed to get field for %s %s %s", current_class_name, field, sig);
		*failed = 1;
	}

	return fid;
}

static jmethodID get_method(int *failed, JNIEnv *env, const char *method, const char *sig)
{
	jmethodID mid;

	if (*failed || current_class == NULL)
		return NULL;

	mid = (*env)->GetMethodID(env, current_class, method, sig);
	if (mid == 0)
	{
		LOGI("Failed to get method for %s %s %s", current_class_name, method, sig);
		*failed = 1;
	}

	return mid;
}

static jmethodID get_static_method(int *failed, JNIEnv *env, const char *method, const char *sig)
{
	jmethodID mid;

	if (*failed || current_class == NULL)
		return NULL;

	mid = (*env)->GetStaticMethodID(env, current_class, method, sig);
	if (mid == 0)
	{
		LOGI("Failed to get static method for %s %s %s", current_class_name, method, sig);
		*failed = 1;
	}

	return mid;
}

static int find_fids(JNIEnv *env)
{
	int err = 0;

	cls_Annot = get_class(&err, env, PKG"Annotation");
	fid_Annot_pointer = get_field(&err, env, "pointer", "J");
	mid_Annot_init = get_method(&err, env, "<init>", "(J)V");

	cls_ColorSpace = get_class(&err, env, PKG"ColorSpace");
	fid_ColorSpace_pointer = get_field(&err, env, "pointer", "J");
	mid_ColorSpace_init = get_method(&err, env, "<init>", "(J)V");
	mid_ColorSpace_fromPointer = get_static_method(&err, env, "fromPointer", "(J)L"PKG"ColorSpace;");

	cls_Cookie = get_class(&err, env, PKG"Cookie");
	fid_Cookie_pointer = get_field(&err, env, "pointer", "J");

	cls_Device = get_class(&err, env, PKG"Device");
	fid_Device_pointer = get_field(&err, env, "pointer", "J");
	mid_Device_fillPath = get_method(&err, env, "fillPath", "(L"PKG"Path;ZL"PKG"Matrix;L"PKG"ColorSpace;[FF)V");
	mid_Device_strokePath = get_method(&err, env, "strokePath", "(L"PKG"Path;L"PKG"StrokeState;L"PKG"Matrix;L"PKG"ColorSpace;[FF)V");
	mid_Device_clipPath = get_method(&err, env, "clipPath", "(L"PKG"Path;ZL"PKG"Matrix;)V");
	mid_Device_clipStrokePath = get_method(&err, env, "clipStrokePath", "(L"PKG"Path;L"PKG"StrokeState;L"PKG"Matrix;)V");
	mid_Device_fillText = get_method(&err, env, "fillText", "(L"PKG"Text;L"PKG"Matrix;L"PKG"ColorSpace;[FF)V");
	mid_Device_strokeText = get_method(&err, env, "strokeText", "(L"PKG"Text;L"PKG"StrokeState;L"PKG"Matrix;L"PKG"ColorSpace;[FF)V");
	mid_Device_clipText = get_method(&err, env, "clipText", "(L"PKG"Text;L"PKG"Matrix;)V");
	mid_Device_clipStrokeText = get_method(&err, env, "clipStrokeText", "(L"PKG"Text;L"PKG"StrokeState;L"PKG"Matrix;)V");
	mid_Device_ignoreText = get_method(&err, env, "ignoreText", "(L"PKG"Text;L"PKG"Matrix;)V");
	mid_Device_fillShade = get_method(&err, env, "fillShade", "(L"PKG"Shade;L"PKG"Matrix;F)V");
	mid_Device_fillImage = get_method(&err, env, "fillImage", "(L"PKG"Image;L"PKG"Matrix;F)V");
	mid_Device_fillImageMask = get_method(&err, env, "fillImageMask", "(L"PKG"Image;L"PKG"Matrix;L"PKG"ColorSpace;[FF)V");
	mid_Device_clipImageMask = get_method(&err, env, "clipImageMask", "(L"PKG"Image;L"PKG"Matrix;)V");
	mid_Device_popClip = get_method(&err, env, "popClip", "()V");
	mid_Device_beginMask = get_method(&err, env, "beginMask", "(L"PKG"Rect;ZL"PKG"ColorSpace;[F)V");
	mid_Device_endMask = get_method(&err, env, "endMask", "()V");
	mid_Device_beginGroup = get_method(&err, env, "beginGroup", "(L"PKG"Rect;ZZIF)V");
	mid_Device_endGroup = get_method(&err, env, "endGroup", "()V");
	mid_Device_beginTile = get_method(&err, env, "beginTile", "(L"PKG"Rect;L"PKG"Rect;FFL"PKG"Matrix;I)I");
	mid_Device_endTile = get_method(&err, env, "endTile", "()V");

	cls_NativeDevice = get_class(&err, env, PKG"NativeDevice");
	fid_NativeDevice_nativeResource = get_field(&err, env, "nativeResource", "Ljava/lang/Object;");
	fid_NativeDevice_nativeInfo = get_field(&err, env, "nativeInfo", "J");

	cls_DisplayList = get_class(&err, env, PKG"DisplayList");
	fid_DisplayList_pointer = get_field(&err, env, "pointer", "J");

	cls_Document = get_class(&err, env, PKG"Document");
	fid_Document_pointer = get_field(&err, env, "pointer", "J");

	cls_Font = get_class(&err, env, PKG"Font");
	fid_Font_pointer = get_field(&err, env, "pointer", "J");
	mid_Font_init = get_method(&err, env, "<init>", "(J)V");

	cls_Image = get_class(&err, env, PKG"Image");
	fid_Image_pointer = get_field(&err, env, "pointer", "J");
	mid_Image_init = get_method(&err, env, "<init>", "(J)V");

	cls_Link = get_class(&err, env, PKG"Link");
	fid_Link_pointer = get_field(&err, env, "pointer", "J");

	cls_Matrix = get_class(&err, env, PKG"Matrix");
	fid_Matrix_a = get_field(&err, env, "a", "F");
	fid_Matrix_b = get_field(&err, env, "b", "F");
	fid_Matrix_c = get_field(&err, env, "c", "F");
	fid_Matrix_d = get_field(&err, env, "d", "F");
	fid_Matrix_e = get_field(&err, env, "e", "F");
	fid_Matrix_f = get_field(&err, env, "f", "F");
	mid_Matrix_init = get_method(&err, env, "<init>", "(FFFFFF)V");

	cls_Outline = get_class(&err, env, PKG"Outline");
	fid_Outline_pointer = get_field(&err, env, "pointer", "J");
	mid_Outline_init = get_method(&err, env, "<init>", "(J)V");

	cls_Page = get_class(&err, env, PKG"Page");
	fid_Page_pointer = get_field(&err, env, "pointer", "J");
	fid_Page_nativeAnnots = get_field(&err, env, "nativeAnnots", "[L"PKG"Annotation;");
	mid_Page_init = get_method(&err, env, "<init>", "(J)V");

	cls_Path = get_class(&err, env, PKG"Path");
	fid_Path_pointer = get_field(&err, env, "pointer", "J");
	mid_Path_init = get_method(&err, env, "<init>", "(J)V");

	cls_Pixmap = get_class(&err, env, PKG"Pixmap");
	fid_Pixmap_pointer = get_field(&err, env, "pointer", "J");
	mid_Pixmap_init = get_method(&err, env, "<init>", "(J)V");

	cls_Point = get_class(&err, env, PKG"Point");
	mid_Point_init = get_method(&err, env, "<init>", "(FF)V");

	cls_PathWalker = get_class(&err, env, PKG"PathWalker");
	mid_PathWalker_moveTo = get_method(&err, env, "moveTo", "(FF)V");
	mid_PathWalker_lineTo = get_method(&err, env, "lineTo", "(FF)V");
	mid_PathWalker_curveTo = get_method(&err, env, "curveTo", "(FFFFFF)V");
	mid_PathWalker_closePath = get_method(&err, env, "closePath", "()V");

	cls_Rect = get_class(&err, env, PKG"Rect");
	fid_Rect_x0 = get_field(&err, env, "x0", "F");
	fid_Rect_x1 = get_field(&err, env, "x1", "F");
	fid_Rect_y0 = get_field(&err, env, "y0", "F");
	fid_Rect_y1 = get_field(&err, env, "y1", "F");
	mid_Rect_init = get_method(&err, env, "<init>", "(FFFF)V");

	cls_Shade = get_class(&err, env, PKG"Shade");
	fid_Shade_pointer = get_field(&err, env, "pointer", "J");
	mid_Shade_init = get_method(&err, env, "<init>", "(J)V");

	cls_StrokeState = get_class(&err, env, PKG"StrokeState");
	fid_StrokeState_pointer = get_field(&err, env, "pointer", "J");
	mid_StrokeState_init = get_method(&err, env, "<init>", "(J)V");

	cls_Text = get_class(&err, env, PKG"Text");
	fid_Text_pointer = get_field(&err, env, "pointer", "J");
	mid_Text_init = get_method(&err, env, "<init>", "(J)V");

	cls_TextWalker = get_class(&err, env, PKG"TextWalker");
	mid_TextWalker_showGlyph = get_method(&err, env, "showGlyph", "(L"PKG"Font;L"PKG"Matrix;IIZ)V");

	cls_TryLaterException = get_class(&err, env, PKG"TryLaterException");

	/* Standard Java classes */

	cls_Object = get_class(&err, env, "java/lang/Object");
	mid_Object_toString = get_method(&err, env, "toString", "()Ljava/lang/String;");

	cls_Exception = get_class(&err, env, "java/lang/Exception");

	cls_OutOfMemoryError = get_class(&err, env, "java/lang/OutOfMemoryError");

	return err;
}

static void lose_fids(JNIEnv *env)
{
	(*env)->DeleteGlobalRef(env, cls_Annot);
	(*env)->DeleteGlobalRef(env, cls_ColorSpace);
	(*env)->DeleteGlobalRef(env, cls_Cookie);
	(*env)->DeleteGlobalRef(env, cls_Device);
	(*env)->DeleteGlobalRef(env, cls_DisplayList);
	(*env)->DeleteGlobalRef(env, cls_Document);
	(*env)->DeleteGlobalRef(env, cls_Exception);
	(*env)->DeleteGlobalRef(env, cls_Font);
	(*env)->DeleteGlobalRef(env, cls_Image);
	(*env)->DeleteGlobalRef(env, cls_Link);
	(*env)->DeleteGlobalRef(env, cls_Matrix);
	(*env)->DeleteGlobalRef(env, cls_NativeDevice);
	(*env)->DeleteGlobalRef(env, cls_Object);
	(*env)->DeleteGlobalRef(env, cls_OutOfMemoryError);
	(*env)->DeleteGlobalRef(env, cls_Outline);
	(*env)->DeleteGlobalRef(env, cls_Page);
	(*env)->DeleteGlobalRef(env, cls_Path);
	(*env)->DeleteGlobalRef(env, cls_PathWalker);
	(*env)->DeleteGlobalRef(env, cls_Pixmap);
	(*env)->DeleteGlobalRef(env, cls_Point);
	(*env)->DeleteGlobalRef(env, cls_Rect);
	(*env)->DeleteGlobalRef(env, cls_Shade);
	(*env)->DeleteGlobalRef(env, cls_StrokeState);
	(*env)->DeleteGlobalRef(env, cls_Text);
	(*env)->DeleteGlobalRef(env, cls_TryLaterException);
}

/* Put the fz_context in thread-local storage */

#ifdef _WIN32
static CRITICAL_SECTION mutexes[FZ_LOCK_MAX];
#else
static pthread_mutex_t mutexes[FZ_LOCK_MAX];
#endif

static void lock(void *user, int lock)
{
#ifdef _WIN32
	EnterCriticalSection(&mutexes[lock]);
#else
	(void)pthread_mutex_lock(&mutexes[lock]);
#endif
}

static void unlock(void *user, int lock)
{
#ifdef _WIN32
	LeaveCriticalSection(&mutexes[lock]);
#else
	(void)pthread_mutex_unlock(&mutexes[lock]);
#endif
}

static const fz_locks_context locks =
{
	NULL, /* user */
	lock,
	unlock
};

static void fin_base_context(JNIEnv *env)
{
	int i;

	for (i = 0; i < FZ_LOCK_MAX; i++)
#ifdef _WIN32
		DeleteCriticalSection(&mutexes[i]);
#else
		(void)pthread_mutex_destroy(&mutexes[i]);
#endif

	fz_drop_context(base_context);
	base_context = NULL;
}

static int init_base_context(JNIEnv *env)
{
	int i;

#ifdef _WIN32
	context_key = TlsAlloc();
	if (context_key == TLS_OUT_OF_INDEXES)
		return -1;
#else
	pthread_key_create(&context_key, NULL);
#endif

	for (i = 0; i < FZ_LOCK_MAX; i++)
#ifdef _WIN32
		InitializeCriticalSection(&mutexes[i]);
#else
		(void)pthread_mutex_init(&mutexes[i], NULL);
#endif

	base_context = fz_new_context(NULL, &locks, FZ_STORE_DEFAULT);
	if (base_context == NULL)
		return -1;

	fz_register_document_handlers(base_context);

	return 0;
}

static fz_context *get_context(JNIEnv *env)
{
	fz_context *ctx = (fz_context *)
#ifdef _WIN32
		TlsGetValue(context_key);
#else
		pthread_getspecific(context_key);
#endif

	if (ctx != NULL)
		return ctx;

	ctx = fz_clone_context(base_context);
	if (ctx == NULL)
	{
		jni_throw_oom(env, "Failed to clone fz_context");
		return NULL;
	}
#ifdef _WIN32
	TlsSetValue(context_key, ctx);
#else
	pthread_setspecific(context_key, ctx);
#endif
	return ctx;
}

JNIEXPORT jint JNICALL
JNI_OnLoad(JavaVM *vm, void *reserved)
{
	JNIEnv *env;

	if ((*vm)->GetEnv(vm, (void **)&env, MY_JNI_VERSION) != JNI_OK)
		return -1;

	return MY_JNI_VERSION;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
	JNIEnv *env;

	if ((*vm)->GetEnv(vm, (void **)&env, MY_JNI_VERSION) != JNI_OK)
		return; /* If this fails, we're really in trouble! */

	fz_drop_context(base_context);
	base_context = NULL;
	lose_fids(env);
}

JNIEXPORT jint JNICALL
FUN(Context_initNative)(JNIEnv *env, jclass cls)
{
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

	return 0;
}

/* Conversion functions: C to Java. These all throw fitz exceptions. */

static inline jobject to_Matrix(fz_context *ctx, JNIEnv *env, const fz_matrix *mat)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Matrix, mid_Matrix_init, mat->a, mat->b, mat->c, mat->d, mat->e, mat->f);
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	return jobj;
}

static inline jobject to_Rect(fz_context *ctx, JNIEnv *env, const fz_rect *rect)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Rect, mid_Rect_init, rect->x0, rect->y0, rect->x1, rect->y1);
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	return jobj;
}

static inline jobject to_Point(fz_context *ctx, JNIEnv *env, fz_point point)
{
	jobject jpoint;

	if (ctx == NULL)
		return NULL;

	jpoint = (*env)->NewObject(env, cls_Point, mid_Point_init, point.x, point.y);
	if (jpoint == NULL)
		fz_throw_java(ctx, env);

	return jpoint;
}

static inline jfloatArray to_jfloatArray(fz_context *ctx, JNIEnv *env, const float *color, jint n)
{
	jfloatArray arr;

	if (ctx == NULL)
		return NULL;

	arr = (*env)->NewFloatArray(env, n);
	if (arr == NULL)
		fz_throw_java(ctx, env);

	(*env)->SetFloatArrayRegion(env, arr, 0, n, color);

	return arr;
}

static inline jobject to_Annotation(fz_context *ctx, JNIEnv *env, fz_annot *annot)
{
	jobject jannot;

	if (ctx == NULL || annot == NULL)
		return NULL;

	jannot = (*env)->NewObject(env, cls_Annot, mid_Annot_init, jlong_cast(annot));
	if (jannot == NULL)
		fz_throw_java(ctx, env);

	fz_keep_annot(ctx, annot);

	return jannot;
}

static inline jobject to_ColorSpace(fz_context *ctx, JNIEnv *env, fz_colorspace *cs)
{
	jobject jobj;

	if (ctx == NULL || cs == NULL)
		return NULL;

	jobj = (*env)->CallStaticObjectMethod(env, cls_ColorSpace, mid_ColorSpace_fromPointer, jlong_cast(cs));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_colorspace(ctx, cs);

	return jobj;
}

/* don't throw fitz exceptions */
static inline jobject to_Font_safe(fz_context *ctx, JNIEnv *env, fz_font *font)
{
	jobject jfont;

	if (ctx == NULL || font == NULL)
		return NULL;

	jfont = (*env)->NewObject(env, cls_Font, mid_Font_init, jlong_cast(font));
	if (jfont != NULL)
		fz_keep_font(ctx, font);

	return jfont;
}

static inline jobject to_Image(fz_context *ctx, JNIEnv *env, fz_image *img)
{
	jobject jobj;

	if (ctx == NULL || img == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Image, mid_Image_init, jlong_cast(img));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_image(ctx, img);

	return jobj;
}

#if 0
static inline jobject to_Outline(fz_context *ctx, JNIEnv *env, fz_outline *outline)
{
	jobject joutline;

	if (ctx == NULL || outline == NULL)
		return NULL;

	joutline = (*env)->NewObject(env, cls_Outline, mid_Outline_init, jlong_cast(outline));
	if (joutline == NULL)
		fz_throw_java(ctx, env);

	fz_keep_outline(ctx, outline);

	return joutline;
}
#endif

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Outline_safe(fz_context *ctx, JNIEnv *env, fz_outline *outline)
{
	jobject joutline;

	if (ctx == NULL || outline == NULL)
		return NULL;

	joutline = (*env)->NewObject(env, cls_Outline, mid_Outline_init, jlong_cast(outline));
	if (joutline == NULL)
	{
		fz_drop_outline(ctx, outline);
		return NULL;
	}

	return joutline;
}

#if 0
static inline jobject to_Page(fz_context *ctx, JNIEnv *env, fz_page *page)
{
	jobject jobj;

	if (ctx == NULL || page == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Page, mid_Page_init, jlong_cast(page));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_page(ctx, page);

	return jobj;
}
#endif

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Page_safe(fz_context *ctx, JNIEnv *env, fz_page *page)
{
	jobject jobj;

	if (ctx == NULL || page == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Page, mid_Page_init, jlong_cast(page));
	if (jobj == NULL)
	{
		fz_drop_page(ctx, page);
		return NULL;
	}

	return jobj;
}

static inline jobject to_Path(fz_context *ctx, JNIEnv *env, const fz_path *path)
{
	jobject jobj;

	if (ctx == NULL || path == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Path, mid_Path_init, jlong_cast(path));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_path(ctx, path);

	return jobj;
}

#if 0
static inline jobject to_Pixmap(fz_context *ctx, JNIEnv *env, fz_pixmap *pixmap)
{
	jobject jobj;

	if (ctx == NULL || pixmap == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Pixmap, mid_Pixmap_init, jlong_cast(pixmap));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_pixmap(ctx, pixmap);

	return jobj;
}
#endif

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Pixmap_safe(fz_context *ctx, JNIEnv *env, fz_pixmap *pixmap)
{
	jobject jobj;

	if (ctx == NULL || pixmap == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Pixmap, mid_Pixmap_init, jlong_cast(pixmap));
	if (jobj == NULL)
	{
		fz_drop_pixmap(ctx, pixmap);
		return NULL;
	}

	return jobj;
}

static inline jobject to_Shade(fz_context *ctx, JNIEnv *env, fz_shade *shade)
{
	jobject jobj;

	if (ctx == NULL || shade == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Shade, mid_Shade_init, jlong_cast(shade));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_shade(ctx, shade);

	return jobj;
}

static inline jobject to_StrokeState(fz_context *ctx, JNIEnv *env, const fz_stroke_state *state)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_StrokeState, mid_StrokeState_init, jlong_cast(state));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_stroke_state(ctx, state);

	return jobj;
}

static inline jobject to_Text(fz_context *ctx, JNIEnv *env, const fz_text *text)
{
	jobject jobj;

	if (ctx == NULL)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Text, mid_Text_init, jlong_cast(text));
	if (jobj == NULL)
		fz_throw_java(ctx, env);

	fz_keep_text(ctx, text);

	return jobj;
}

/* Conversion functions: Java to C. These all throw java exceptions. */

static inline fz_matrix from_Matrix(JNIEnv *env, jobject jmat)
{
	fz_matrix mat;

	mat.a = (*env)->GetFloatField(env, jmat, fid_Matrix_a);
	mat.b = (*env)->GetFloatField(env, jmat, fid_Matrix_b);
	mat.c = (*env)->GetFloatField(env, jmat, fid_Matrix_c);
	mat.d = (*env)->GetFloatField(env, jmat, fid_Matrix_d);
	mat.e = (*env)->GetFloatField(env, jmat, fid_Matrix_e);
	mat.f = (*env)->GetFloatField(env, jmat, fid_Matrix_f);

	return mat;
}

static inline fz_rect from_Rect(JNIEnv *env, jobject jrect)
{
	fz_rect rect;

	rect.x0 = (*env)->GetFloatField(env, jrect, fid_Rect_x0);
	rect.x1 = (*env)->GetFloatField(env, jrect, fid_Rect_x1);
	rect.y0 = (*env)->GetFloatField(env, jrect, fid_Rect_y0);
	rect.y1 = (*env)->GetFloatField(env, jrect, fid_Rect_y1);

	return rect;
}

static inline void from_jfloatArray(JNIEnv *env, float *color, jint n, jfloatArray jcolor)
{
	jsize len = (*env)->GetArrayLength(env, jcolor);
	if (len > n)
		len = n;
	(*env)->GetFloatArrayRegion(env, jcolor, 0, len, color);
	if (len < n)
		memset(color+len, 0, (n-len)*sizeof(float));
}

static inline fz_annot *from_Annotation(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_annot *, (*env)->GetLongField(env, jobj, fid_Annot_pointer));
}

static inline fz_cookie *from_Cookie(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_cookie *, (*env)->GetLongField(env, jobj, fid_Cookie_pointer));
}

static inline fz_colorspace *from_ColorSpace(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_colorspace *, (*env)->GetLongField(env, jobj, fid_ColorSpace_pointer));
}

static fz_device *from_Device(JNIEnv *env, jobject jobj, fz_context *ctx)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_device *, (*env)->GetLongField(env, jobj, fid_Device_pointer));
}

static inline fz_display_list *from_DisplayList(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_display_list *, (*env)->GetLongField(env, jobj, fid_DisplayList_pointer));
}

static inline fz_document *from_Document(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_document *, (*env)->GetLongField(env, jobj, fid_Document_pointer));
}

static inline fz_font *from_Font(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_font *, (*env)->GetLongField(env, jobj, fid_Font_pointer));
}

static inline fz_image *from_Image(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_image *, (*env)->GetLongField(env, jobj, fid_Image_pointer));
}

static inline fz_link *from_Link(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_link *, (*env)->GetLongField(env, jobj, fid_Link_pointer));
}

static inline fz_outline *from_Outline(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_outline *, (*env)->GetLongField(env, jobj, fid_Outline_pointer));
}

static inline fz_page *from_Page(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_page *, (*env)->GetLongField(env, jobj, fid_Page_pointer));
}

static inline fz_path *from_Path(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_path *, (*env)->GetLongField(env, jobj, fid_Path_pointer));
}

static inline fz_pixmap *from_Pixmap(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_pixmap *, (*env)->GetLongField(env, jobj, fid_Pixmap_pointer));
}

static inline fz_shade *from_Shade(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_shade *, (*env)->GetLongField(env, jobj, fid_Shade_pointer));
}

static inline fz_stroke_state *from_StrokeState(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_stroke_state *, (*env)->GetLongField(env, jobj, fid_StrokeState_pointer));
}

static inline fz_text *from_Text(JNIEnv *env, jobject jobj)
{
	if (jobj == NULL)
		return NULL;
	return CAST(fz_text *, (*env)->GetLongField(env, jobj, fid_Text_pointer));
}

/*
	Devices can either be implemented in C, or in Java.
	We therefore have to think about 4 possible call combinations.

	1) C -> C:
	The standard mupdf case. No special worries here.
	2) C -> Java:
	This can only happen when we call run on a page/annotation/
	displaylist. We need to ensure that the java Device has an
	appropriate fz_java_device generated for it, which is done by the
	Device constructor. The 'run' calls take care to lock/unlock for us.
	3) Java -> C:
	The C device will have a java shim (a subclass of NativeDevice).
	All calls will go through the device methods in NativeDevice,
	which converts the java objects to C ones, and lock/unlock
	any underlying objects as required.
	4) Java -> Java:
	No special worries.
 */

typedef struct
{
	fz_device super;
	JNIEnv *env;
	jobject self;
}
fz_java_device;

static void
fz_java_device_fill_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm, fz_colorspace *cs, const float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = to_Path(ctx, env, path);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jobject jctm = to_Matrix(ctx, env, ctm);
	jfloatArray jcolor = to_jfloatArray(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_fillPath, jpath, (jboolean)even_odd, jctm, jcs, jcolor, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *state, const fz_matrix *ctm, fz_colorspace *cs, const float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = to_Path(ctx, env, path);
	jobject jstate = to_StrokeState(ctx, env, state);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jobject jctm = to_Matrix(ctx, env, ctm);
	jfloatArray jcolor = to_jfloatArray(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_strokePath, jpath, jstate, jctm, jcs, jcolor, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_clip_path(fz_context *ctx, fz_device *dev, const fz_path *path, int even_odd, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = to_Path(ctx, env, path);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_clipPath, jpath, (jboolean)even_odd, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_clip_stroke_path(fz_context *ctx, fz_device *dev, const fz_path *path, const fz_stroke_state *state, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jpath = to_Path(ctx, env, path);
	jobject jstate = to_StrokeState(ctx, env, state);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_clipStrokePath, jpath, jstate, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_fill_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm, fz_colorspace *cs, const float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = to_Text(ctx, env, text);
	jobject jctm = to_Matrix(ctx, env, ctm);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jfloatArray jcolor = to_jfloatArray(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_fillText, jtext, jctm, jcs, jcolor, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *state, const fz_matrix *ctm, fz_colorspace *cs, const float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = to_Text(ctx, env, text);
	jobject jstate = to_StrokeState(ctx, env, state);
	jobject jctm = to_Matrix(ctx, env, ctm);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jfloatArray jcolor = to_jfloatArray(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_strokeText, jtext, jstate, jctm, jcs, jcolor, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_clip_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = to_Text(ctx, env, text);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_clipText, jtext, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_clip_stroke_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_stroke_state *state, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = to_Text(ctx, env, text);
	jobject jstate = to_StrokeState(ctx, env, state);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_clipStrokeText, jtext, jstate, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_ignore_text(fz_context *ctx, fz_device *dev, const fz_text *text, const fz_matrix *ctm)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jtext = to_Text(ctx, env, text);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_ignoreText, jtext, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_fill_shade(fz_context *ctx, fz_device *dev, fz_shade *shd, const fz_matrix *ctm, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jshd = to_Shade(ctx, env, shd);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_fillShade, jshd, jctm, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_fill_image(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = to_Image(ctx, env, img);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_fillImage, jimg, jctm, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_fill_image_mask(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, fz_colorspace *cs, const float *color, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = to_Image(ctx, env, img);
	jobject jctm = to_Matrix(ctx, env, ctm);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jfloatArray jcolor = to_jfloatArray(ctx, env, color, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_fillImageMask, jimg, jctm, jcs, jcolor, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_clip_image_mask(fz_context *ctx, fz_device *dev, fz_image *img, const fz_matrix *ctm, const fz_rect *scissor)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jimg = to_Image(ctx, env, img);
	jobject jctm = to_Matrix(ctx, env, ctm);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_clipImageMask, jimg, jctm);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_pop_clip(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_popClip);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_begin_mask(fz_context *ctx, fz_device *dev, const fz_rect *rect, int luminosity, fz_colorspace *cs, const float *bc)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jrect = to_Rect(ctx, env, rect);
	jobject jcs = to_ColorSpace(ctx, env, cs);
	jfloatArray jbc = to_jfloatArray(ctx, env, bc, cs ? cs->n : FZ_MAX_COLORS);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_beginMask, jrect, (jint)luminosity, jcs, jbc);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_end_mask(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_endMask);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_begin_group(fz_context *ctx, fz_device *dev, const fz_rect *rect, int isolated, int knockout, int blendmode, float alpha)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jrect = to_Rect(ctx, env, rect);

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_beginGroup, jrect, (jboolean)isolated, (jboolean)knockout, (jint)blendmode, alpha);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_end_group(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_endGroup);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static int
fz_java_device_begin_tile(fz_context *ctx, fz_device *dev, const fz_rect *area, const fz_rect *view, float xstep, float ystep, const fz_matrix *ctm, int id)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;
	jobject jarea = to_Rect(ctx, env, area);
	jobject jview = to_Rect(ctx, env, view);
	jobject jctm = to_Matrix(ctx, env, ctm);
	int res;

	res = (*env)->CallIntMethod(env, jdev->self, mid_Device_beginTile, jarea, jview, xstep, ystep, jctm, (jint)id);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);

	return res;
}

static void
fz_java_device_end_tile(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->CallVoidMethod(env, jdev->self, mid_Device_endTile);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
fz_java_device_drop(fz_context *ctx, fz_device *dev)
{
	fz_java_device *jdev = (fz_java_device *)dev;
	JNIEnv *env = jdev->env;

	(*env)->DeleteGlobalRef(env, jdev->self);
}

static fz_device *fz_new_java_device(fz_context *ctx, JNIEnv *env, jobject self)
{
	fz_java_device *dev = NULL;

	fz_try(ctx)
	{
		dev = fz_new_device(ctx, sizeof(fz_java_device));
		dev->env = env;

		dev->self = (*env)->NewGlobalRef(env, self);

		dev->super.drop_device = fz_java_device_drop;

		dev->super.fill_path = fz_java_device_fill_path;
		dev->super.stroke_path = fz_java_device_stroke_path;
		dev->super.clip_path = fz_java_device_clip_path;
		dev->super.clip_stroke_path = fz_java_device_clip_stroke_path;

		dev->super.fill_text = fz_java_device_fill_text;
		dev->super.stroke_text = fz_java_device_stroke_text;
		dev->super.clip_text = fz_java_device_clip_text;
		dev->super.clip_stroke_text = fz_java_device_clip_stroke_text;
		dev->super.ignore_text = fz_java_device_ignore_text;

		dev->super.fill_shade = fz_java_device_fill_shade;
		dev->super.fill_image = fz_java_device_fill_image;
		dev->super.fill_image_mask = fz_java_device_fill_image_mask;
		dev->super.clip_image_mask = fz_java_device_clip_image_mask;

		dev->super.pop_clip = fz_java_device_pop_clip;

		dev->super.begin_mask = fz_java_device_begin_mask;
		dev->super.end_mask = fz_java_device_end_mask;
		dev->super.begin_group = fz_java_device_begin_group;
		dev->super.end_group = fz_java_device_end_group;

		dev->super.begin_tile = fz_java_device_begin_tile;
		dev->super.end_tile = fz_java_device_end_tile;
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}

	return (fz_device*)dev;
}

JNIEXPORT jlong JNICALL
FUN(Device_newNative)(JNIEnv *env, jclass self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		dev = fz_new_java_device(ctx, env, self);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(dev);
}

JNIEXPORT void JNICALL
FUN(Device_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);

	if (ctx == NULL || dev == NULL)
		return;

	fz_drop_device(ctx, dev);
}

/* Device Interface */

typedef struct NativeDeviceInfo NativeDeviceInfo;

typedef void (NativeDeviceLockFn)(JNIEnv *env, NativeDeviceInfo *info);
typedef void (NativeDeviceUnlockFn)(JNIEnv *env, NativeDeviceInfo *info);

struct NativeDeviceInfo
{
	/* Some devices (like the AndroidDrawDevice, or DrawDevice) need
	 * to lock/unlock the java object around device calls. We have functions
	 * here to do that. Other devices (like the DisplayList device) need
	 * no such locking, so these are NULL. */
	NativeDeviceLockFn *lock; /* Function to lock */
	NativeDeviceUnlockFn *unlock; /* Function to unlock */
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

static NativeDeviceInfo *lockNativeDevice(JNIEnv *env, jobject self)
{
	NativeDeviceInfo *info = NULL;

	if (!(*env)->IsInstanceOf(env, self, cls_NativeDevice))
		return NULL;

	info = CAST(NativeDeviceInfo *, (*env)->GetLongField(env, self, fid_NativeDevice_nativeInfo));
	if (info == NULL)
	{
		/* Some devices (like the Displaylist device) need no locking, so have no info. */
		return NULL;
	}
	info->object = (*env)->GetObjectField(env, self, fid_NativeDevice_nativeResource);

	info->lock(env, info);

	return info;
}

static void unlockNativeDevice(JNIEnv *env, NativeDeviceInfo *info)
{
	if (info != NULL)
		info->unlock(env, info);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *ninfo;

	if (ctx == NULL || dev == NULL)
		return;

	FUN(Device_finalize)(env, self); /* Call super.finalize() */

	ninfo = CAST(NativeDeviceInfo *, (*env)->GetLongField(env, self, fid_NativeDevice_nativeInfo));
	if (ninfo != NULL)
	{
		fz_drop_pixmap(ctx, ninfo->pixmap);
		fz_free(ctx, ninfo);
	}
}

JNIEXPORT void JNICALL
FUN(NativeDevice_close)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_close_device(ctx, dev);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillPath)(JNIEnv *env, jobject self, jobject jpath, jboolean even_odd, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_path(ctx, dev, path, even_odd, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_strokePath)(JNIEnv *env, jobject self, jobject jpath, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_stroke_path(ctx, dev, path, stroke, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipPath)(JNIEnv *env, jobject self, jobject jpath, jboolean even_odd, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_path(ctx, dev, path, even_odd, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipStrokePath)(JNIEnv *env, jobject self, jobject jpath, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_stroke_path(ctx, dev, path, stroke, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_text(ctx, dev, text, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_strokeText)(JNIEnv *env, jobject self, jobject jtext, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_stroke_text(ctx, dev, text, stroke, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_text(ctx, dev, text, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipStrokeText)(JNIEnv *env, jobject self, jobject jtext, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_text *text = from_Text(env, jtext);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_stroke_text(ctx, dev, text, stroke, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_ignoreText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_ignore_text(ctx, dev, text, &ctm);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillShade)(JNIEnv *env, jobject self, jobject jshade, jobject jctm, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_shade *shade = from_Shade(env, jshade);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_shade(ctx, dev, shade, &ctm, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillImage)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_image *image = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_image(ctx, dev, image, &ctm, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, jobject jcs, jfloatArray jcolor, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_image *image = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_image_mask(ctx, dev, image, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_image *image = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_image_mask(ctx, dev, image, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_popClip)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_pop_clip(ctx, dev);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_beginMask)(JNIEnv *env, jobject self, jobject jrect, jboolean luminosity, jobject jcs, jfloatArray jcolor)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_rect rect = from_Rect(env, jrect);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_begin_mask(ctx, dev, &rect, luminosity, cs, color);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_endMask)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_end_mask(ctx, dev);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_beginGroup)(JNIEnv *env, jobject self, jobject jrect, jboolean isolated, jboolean knockout, jint blendmode, float alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_rect rect = from_Rect(env, jrect);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_begin_group(ctx, dev, &rect, isolated, knockout, blendmode, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_endGroup)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_end_group(ctx, dev);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jint JNICALL
FUN(NativeDevice_beginTile)(JNIEnv *env, jobject self, jobject jarea, jobject jview, float xstep, float ystep, jobject jctm, jint id)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_rect area = from_Rect(env, jarea);
	fz_rect view = from_Rect(env, jview);
	NativeDeviceInfo *info;
	int i = 0;

	if (ctx == NULL || dev == NULL)
		return 0;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		i = fz_begin_tile_id(ctx, dev, &area, &view, xstep, ystep, &ctm, id);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return i;
}

JNIEXPORT void JNICALL
FUN(NativeDevice_endTile)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self, ctx);
	NativeDeviceInfo *info;

	if (ctx == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_end_tile(ctx, dev);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jlong JNICALL
FUN(DrawDevice_newNative)(JNIEnv *env, jclass self, jobject pixmap_)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, pixmap_);
	fz_device *device = NULL;

	if (ctx == NULL || pixmap == NULL)
		return 0;

	fz_try(ctx)
		device = fz_new_draw_device(ctx, NULL, pixmap);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(device);
}

JNIEXPORT jlong JNICALL
FUN(DisplayListDevice_newNative)(JNIEnv *env, jclass self, jobject jlist)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, jlist);
	fz_device *device = NULL;

	if (ctx == NULL || list == NULL)
		return 0;

	fz_try(ctx)
		device = fz_new_list_device(ctx, list);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(device);
}

#ifdef HAVE_ANDROID

static jlong
newNativeAndroidDrawDevice(JNIEnv *env, jobject self, fz_context *ctx, jobject obj, jint width, jint height, NativeDeviceLockFn *lock, NativeDeviceUnlockFn *unlock, jint pageX0, jint pageY0, jint pageX1, jint pageY1, jint patchX0, jint patchY0, jint patchX1, jint patchY1)
{
	fz_device *device = NULL;
	fz_pixmap *pixmap = NULL;
	unsigned char dummy;
	NativeDeviceInfo *ninfo = NULL;
	fz_irect clip, pixbbox;

	if (ctx == NULL)
		return 0;

	fz_var(pixmap);
	fz_var(ninfo);

	fz_try(ctx)
	{
		LOGI("DrawDeviceNative: bitmap=%d,%d page=%d,%d->%d,%d patch=%d,%d->%d,%d", width, height, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
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

		pixmap = fz_new_pixmap_with_bbox_and_data(ctx, fz_device_rgb(ctx), &pixbbox, 1, &dummy);
		ninfo = fz_malloc(ctx, sizeof(*ninfo));
		ninfo->pixmap = pixmap;
		ninfo->lock = lock;
		ninfo->unlock = unlock;
		ninfo->pageX0 = patchX0;
		ninfo->pageY0 = patchY0;
		ninfo->width = width;
		ninfo->object = obj;
		(*env)->SetLongField(env, self, fid_NativeDevice_nativeInfo, jlong_cast(ninfo));
		(*env)->SetObjectField(env, self, fid_NativeDevice_nativeResource, obj);
		lockNativeDevice(env,self);
		fz_clear_pixmap_rect_with_value(ctx, pixmap, 0xff, &clip);
		unlockNativeDevice(env,ninfo);
		device = fz_new_draw_device_with_bbox(ctx, NULL, pixmap, &clip);
	}
	fz_catch(ctx)
	{
		fz_drop_pixmap(ctx, pixmap);
		fz_free(ctx, ninfo);
		jni_rethrow(env, ctx);
	}
	return jlong_cast(device);
}

static void androidDrawDevice_lock(JNIEnv *env, NativeDeviceInfo *info)
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
	pixels += sizeof(int32_t) * (info->pageX0 + info->width * info->pageY0);

	info->pixmap->samples = pixels;
}

static void androidDrawDevice_unlock(JNIEnv *env, NativeDeviceInfo *info)
{
	assert(info != NULL);
	assert(info->object != NULL);

	if (AndroidBitmap_unlockPixels(env, info->object) < 0)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Bitmap unlock failed in DrawDevice call");
	}
}

JNIEXPORT jlong JNICALL
FUN(AndroidDrawDevice_newNative)(JNIEnv *env, jclass self, jobject jbitmap, jint pageX0, jint pageY0, jint pageX1, jint pageY1, jint patchX0, jint patchY0, jint patchX1, jint patchY1)
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

		device = newNativeAndroidDrawDevice(env, self, ctx, jbitmap, info.width, info.height, androidDrawDevice_lock, androidDrawDevice_unlock, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
	}
	return device;
}

#endif

#ifdef HAVE_ANDROID
JNIEXPORT jlong JNICALL
FUN(Image_newImageFromBitmap)(JNIEnv *env, jobject self, jobject jbitmap, jlong jmask)
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

		pixmap = fz_new_pixmap(ctx, fz_device_rgb(ctx), info.width, info.height, 1);
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
#endif

/* ColorSpace Interface */

JNIEXPORT void JNICALL
FUN(ColorSpace_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_colorspace *cs = from_ColorSpace(env, self);

	if (ctx == NULL || cs == NULL)
		return;

	fz_drop_colorspace(ctx, cs);
}

JNIEXPORT jint JNICALL
FUN(ColorSpace_getNumberOfComponents)(JNIEnv *env, jobject self)
{
	fz_colorspace *cs = from_ColorSpace(env, self);

	if (cs == NULL)
		return 0;

	return cs->n;
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceGray)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	return jlong_cast(fz_device_gray(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceRGB)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	return jlong_cast(fz_device_rgb(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceBGR)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	return jlong_cast(fz_device_bgr(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceCMYK)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	return jlong_cast(fz_device_cmyk(ctx));
}

/* Font interface */

JNIEXPORT void JNICALL
FUN(Font_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);

	if (ctx == NULL || font == NULL)
		return;

	fz_drop_font(ctx, font);
}

JNIEXPORT jlong JNICALL
FUN(Font_newNative)(JNIEnv *env, jobject self, jstring jname, jint index)
{
	fz_context *ctx = get_context(env);
	const char *name = NULL;
	fz_font *font = NULL;

	if (ctx == NULL || jname == NULL)
		return 0;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (name == NULL)
		return 0;

	fz_try(ctx)
	{
		const char *data;
		int size;
		data = fz_lookup_base14_font(ctx, name, &size);
		if (data)
			font = fz_new_font_from_memory(ctx, name, data, size, index, 0);
		else
			font = fz_new_font_from_file(ctx, name, name, index, 0);
	}
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(font);
}

JNIEXPORT jstring JNICALL
FUN(Font_getName)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);

	if (ctx == NULL || font == NULL)
		return NULL;

	return (*env)->NewStringUTF(env, font->name);
}

JNIEXPORT jint JNICALL
FUN(Font_encodeCharacter)(JNIEnv *env, jobject self, jint unicode)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);
	jint glyph = 0;

	if (ctx == NULL || font == NULL)
		return 0;

	fz_try(ctx)
		glyph = fz_encode_character(ctx, font, unicode);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return glyph;
}

JNIEXPORT jfloat JNICALL
FUN(Font_advanceGlyph)(JNIEnv *env, jobject self, jint glyph, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);
	float advance = 0;

	if (ctx == NULL || font == NULL)
		return 0;

	fz_try(ctx)
		advance = fz_advance_glyph(ctx, font, glyph, wmode);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return advance;
}

/* Pixmap Interface */

JNIEXPORT void JNICALL
FUN(Pixmap_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (ctx == NULL || pixmap == NULL)
		return;

	fz_drop_pixmap(ctx, pixmap);
}

JNIEXPORT jlong JNICALL
FUN(Pixmap_newNative)(JNIEnv *env, jobject self, jobject colorspace_, jint x, jint y, jint w, jint h, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_colorspace *colorspace = from_ColorSpace(env, colorspace_);

	fz_pixmap *pixmap = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
	{
		pixmap = fz_new_pixmap(ctx, colorspace, w, h, alpha);
		pixmap->x = x;
		pixmap->y = y;
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(pixmap);
}

JNIEXPORT void JNICALL
FUN(Pixmap_clear)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (ctx == NULL || pixmap == NULL)
		return;

	fz_try(ctx)
		fz_clear_pixmap(ctx, pixmap);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Pixmap_clearWithValue)(JNIEnv *env, jobject self, jint value)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (ctx == NULL || pixmap == NULL)
		return;

	fz_try(ctx)
		fz_clear_pixmap_with_value(ctx, pixmap, value);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getX)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->x;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getY)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->y;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getWidth)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->w;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getHeight)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->h;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getNumberOfComponents)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->n;
}

JNIEXPORT jboolean JNICALL
FUN(Pixmap_getAlpha)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->alpha;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getStride)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (ctx == NULL || pixmap == NULL)
		return 0;
	return pixmap->stride;
}

JNIEXPORT jobject JNICALL
FUN(Pixmap_getColorSpace)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	jobject jcolorspace = NULL;

	if (ctx == NULL || pixmap == NULL)
		return 0;

	fz_try(ctx)
	{
		fz_colorspace *colorspace = fz_pixmap_colorspace(ctx, pixmap);
		jcolorspace = to_ColorSpace(ctx, env, colorspace);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jcolorspace;
}

JNIEXPORT jbyteArray JNICALL
FUN(Pixmap_getSamples)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	int size = pixmap->h * pixmap->stride;
	jbyteArray ary;

	if (ctx == NULL || pixmap == NULL)
		return NULL;

	ary = (*env)->NewByteArray(env, size);
	if (!ary)
		return NULL;

	(*env)->SetByteArrayRegion(env, ary, 0, size, (const jbyte *)pixmap->samples);

	return ary;
}

JNIEXPORT jintArray JNICALL
FUN(Pixmap_getPixels)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	int size = pixmap->w * pixmap->h;
	jintArray ary;

	if (ctx == NULL || pixmap == NULL)
		return NULL;

	if (pixmap->n != 4 || !pixmap->alpha)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "invalid colorspace for getPixels (must be RGB/BGR with alpha)");
		return NULL;
	}

	if (size * 4 != pixmap->h * pixmap->stride)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "invalid stride for getPixels");
		return NULL;
	}

	ary = (*env)->NewIntArray(env, size);
	if (!ary)
		return NULL;

	(*env)->SetIntArrayRegion(env, ary, 0, size, (const jint *)pixmap->samples);

	return ary;
}

/* Path Interface */

JNIEXPORT void JNICALL
FUN(Path_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_drop_path(ctx, path);
}

JNIEXPORT jlong JNICALL
FUN(Path_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		path = fz_new_path(ctx);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(path);
}

JNIEXPORT jobject JNICALL
FUN(Path_currentPoint)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);
	jobject jpoint = NULL;

	if (ctx == NULL || path == NULL)
		return NULL;

	fz_try(ctx)
		jpoint = to_Point(ctx, env, fz_currentpoint(ctx, path));
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jpoint;
}

JNIEXPORT void JNICALL
FUN(Path_moveTo)(JNIEnv *env, jobject self, float x, float y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_moveto(ctx, path, x, y);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_lineTo)(JNIEnv *env, jobject self, float x, float y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_lineto(ctx, path, x, y);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveTo)(JNIEnv *env, jobject self, float cx1, float cy1, float cx2, float cy2, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_curveto(ctx, path, cx1, cy1, cx2, cy2, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveToV)(JNIEnv *env, jobject self, float cx, float cy, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_curvetov(ctx, path, cx, cy, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveToY)(JNIEnv *env, jobject self, float cx, float cy, float ex, float ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_curvetoy(ctx, path, cx, cy, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_closePath)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_closepath(ctx, path);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_transform)(JNIEnv *env, jobject self, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);
	fz_matrix ctm = from_Matrix(env, jctm);

	if (ctx == NULL || path == NULL)
		return;

	fz_try(ctx)
		fz_transform_path(ctx, path, &ctm);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jlong JNICALL
FUN(Path_cloneNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *old_path = from_Path(env, self);
	fz_path *new_path = NULL;

	if (ctx == NULL || old_path == NULL)
		return 0;

	fz_try(ctx)
		new_path = fz_clone_path(ctx, old_path);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(new_path);
}

JNIEXPORT jobject JNICALL
FUN(Path_getBounds)(JNIEnv *env, jobject self, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	jobject jrect = NULL;
	fz_rect rect;

	if (ctx == NULL || path == NULL)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_path(ctx, path, stroke, &ctm, &rect));
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jrect;
}

typedef struct {
	JNIEnv *env;
	jobject obj;
} path_walker_state;

static void
pathWalkMoveTo(fz_context *ctx, void *arg, float x, float y)
{
	path_walker_state *state = (path_walker_state *)arg;
	JNIEnv *env = state->env;
	(*env)->CallVoidMethod(env, state->obj, mid_PathWalker_moveTo, x, y);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
pathWalkLineTo(fz_context *ctx, void *arg, float x, float y)
{
	path_walker_state *state = (path_walker_state *)arg;
	JNIEnv *env = state->env;
	(*env)->CallVoidMethod(env, state->obj, mid_PathWalker_lineTo, x, y);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
pathWalkCurveTo(fz_context *ctx, void *arg, float x1, float y1, float x2, float y2, float x3, float y3)
{
	path_walker_state *state = (path_walker_state *)arg;
	JNIEnv *env = state->env;
	(*env)->CallVoidMethod(env, state->obj, mid_PathWalker_curveTo, x1, y1, x2, y2, x3, y3);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static void
pathWalkClosePath(fz_context *ctx, void *arg)
{
	path_walker_state *state = (path_walker_state *) arg;
	JNIEnv *env = state->env;
	(*env)->CallVoidMethod(env, state->obj, mid_PathWalker_closePath);
	if ((*env)->ExceptionCheck(env))
		fz_throw_java(ctx, env);
}

static const fz_path_walker java_path_walker =
{
	pathWalkMoveTo,
	pathWalkLineTo,
	pathWalkCurveTo,
	pathWalkClosePath,
	NULL,
	NULL,
	NULL,
	NULL
};

JNIEXPORT void JNICALL
FUN(Path_walk)(JNIEnv *env, jobject self, jobject obj)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);
	path_walker_state state;

	if (path == NULL || obj == NULL)
		return;

	state.env = env;
	state.obj = obj;

	fz_try(ctx)
		fz_walk_path(ctx, path, &java_path_walker, &state);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

/* StrokeState interface */

JNIEXPORT void JNICALL
FUN(StrokeState_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = from_StrokeState(env, self);

	if (ctx == NULL || stroke == NULL)
		return;

	fz_drop_stroke_state(ctx, stroke);
}

JNIEXPORT jlong JNICALL
FUN(Path_newStrokeState)(JNIEnv *env, jobject self, jint startCap, jint dashCap, jint endCap, jint lineJoin, float lineWidth, float miterLimit, float dashPhase, jfloatArray dash)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = NULL;
	jsize len = (*env)->GetArrayLength(env, dash);

	if (ctx == NULL)
		return 0;

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
		jni_rethrow(env, ctx);

	return jlong_cast(stroke);
}

JNIEXPORT jint JNICALL
FUN(StrokeState_getStartCap)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->start_cap : 0;
}

JNIEXPORT jint JNICALL
FUN(StrokeState_getDashCap)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->dash_cap : 0;
}

JNIEXPORT jint JNICALL
FUN(StrokeState_getEndCap)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->end_cap : 0;
}

JNIEXPORT jint JNICALL
FUN(StrokeState_getLineJoin)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->linejoin : 0;
}

JNIEXPORT float JNICALL
FUN(StrokeState_getLineWidth)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->linewidth : 0;
}

JNIEXPORT float JNICALL
FUN(StrokeState_getMiterLimit)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->miterlimit : 0;
}

JNIEXPORT float JNICALL
FUN(StrokeState_getDashPhase)(JNIEnv *env, jobject self)
{
	fz_stroke_state *stroke = from_StrokeState(env, self);
	return stroke ? stroke->dash_phase : 0;
}

JNIEXPORT jfloatArray JNICALL
FUN(StrokeState_getDashes)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = from_StrokeState(env, self);
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
FUN(Text_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);

	if (ctx == NULL || text == NULL)
		return;

	fz_drop_text(ctx, text);
}

JNIEXPORT jlong JNICALL
FUN(Text_clone)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *old_text = from_Text(env, self);
	fz_text *new_text = NULL;

	if (ctx == NULL || old_text == NULL)
		return 0;

	fz_try(ctx)
		new_text = fz_clone_text(ctx, old_text);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(new_text);
}

JNIEXPORT jlong JNICALL
FUN(Text_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		text = fz_new_text(ctx);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(text);
}

JNIEXPORT jobject JNICALL
FUN(Text_getBounds)(JNIEnv *env, jobject self, jobject jstroke, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	jobject jrect = NULL;
	fz_rect rect;

	if (ctx == NULL || text == NULL)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_text(ctx, text, stroke, &ctm, &rect));
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jrect;
}

JNIEXPORT void JNICALL
FUN(Text_showGlyph)(JNIEnv *env, jobject self, jobject font_, jobject matrix_, jint glyph, jint unicode, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_font *font = from_Font(env, font_);
	fz_matrix trm = from_Matrix(env, matrix_);

	if (ctx == NULL || text == NULL)
		return;

	fz_try(ctx)
		fz_show_glyph(ctx, text, font, &trm, glyph, unicode, wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Text_showString)(JNIEnv *env, jobject self, jobject font_, jobject matrix_, jstring string_, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_font *font = from_Font(env, font_);
	fz_matrix trm = from_Matrix(env, matrix_);
	const char *string;

	if (ctx == NULL || text == NULL)
		return;

	string = (*env)->GetStringUTFChars(env, string_, NULL);
	if (string == NULL)
		return;

	fz_try(ctx)
		fz_show_string(ctx, text, font, &trm, string, wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, string_, string);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	(*env)->SetFloatField(env, matrix_, fid_Matrix_e, trm.e);
	(*env)->SetFloatField(env, matrix_, fid_Matrix_f, trm.f);
}

JNIEXPORT void JNICALL
FUN(Text_walk)(JNIEnv *env, jobject self, jobject walker)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_text_span *span;
	fz_font *font = NULL;
	jobject jfont = NULL;
	jobject jtrm = NULL;
	int i;

	if (!text->head)
		return;

	/* TODO: We reuse the same Matrix object for each call, but should we? */
	jtrm = (*env)->NewObject(env, cls_Matrix, mid_Matrix_init, 1, 0, 0, 1, 0, 0);
	if (!jtrm)
		return;

	for (span = text->head; span; span = span->next)
	{
		if (font != span->font)
		{
			font = span->font;
			jfont = to_Font_safe(ctx, env, font);
			if (!jfont)
				return;
		}

		(*env)->SetFloatField(env, jtrm, fid_Matrix_a, span->trm.a);
		(*env)->SetFloatField(env, jtrm, fid_Matrix_b, span->trm.b);
		(*env)->SetFloatField(env, jtrm, fid_Matrix_c, span->trm.c);
		(*env)->SetFloatField(env, jtrm, fid_Matrix_d, span->trm.d);

		for (i = 0; i < span->len; ++i)
		{
			(*env)->SetFloatField(env, jtrm, fid_Matrix_e, span->items[i].x);
			(*env)->SetFloatField(env, jtrm, fid_Matrix_f, span->items[i].y);

			(*env)->CallVoidMethod(env, walker, mid_TextWalker_showGlyph,
					jfont, jtrm,
					(jint)span->items[i].gid,
					(jint)span->items[i].ucs,
					(jint)span->wmode);

			if ((*env)->ExceptionCheck(env))
				return;
		}
	}
}

/* Image interface */

JNIEXPORT void JNICALL
FUN(Image_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *image = from_Image(env, self);

	if (ctx == NULL || image == NULL)
		return;

	fz_drop_image(ctx, image);
}

JNIEXPORT jlong JNICALL
FUN(Image_newNativeFromPixmap)(JNIEnv *env, jobject self, jobject pixmap_)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, pixmap_);
	fz_image *image = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		image = fz_new_image_from_pixmap(ctx, pixmap, NULL);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(image);
}

JNIEXPORT jlong JNICALL
FUN(Image_newNativeFromFile)(JNIEnv *env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	const char *filename = NULL;
	fz_image *image = NULL;

	if (ctx == NULL || jfilename == NULL)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (filename == NULL)
		return 0;

	fz_try(ctx)
		image = fz_new_image_from_file(ctx, filename);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(image);
}

JNIEXPORT jint JNICALL
FUN(Image_getWidth)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->w : 0;
}

JNIEXPORT jint JNICALL
FUN(Image_getHeight)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->h : 0;
}

JNIEXPORT jint JNICALL
FUN(Image_getNumberOfComponents)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->n : 0;
}

JNIEXPORT jint JNICALL
FUN(Image_getBitsPerComponent)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->bpc : 0;
}

JNIEXPORT jint JNICALL
FUN(Image_getXResolution)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->xres : 0;
}

JNIEXPORT jint JNICALL
FUN(Image_getYResolution)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->yres : 0;
}

JNIEXPORT jboolean JNICALL
FUN(Image_getImageMask)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->imagemask : 0;
}

JNIEXPORT jboolean JNICALL
FUN(Image_getInterpolate)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	return image ? image->interpolate : 0;
}

JNIEXPORT jobject JNICALL
FUN(Image_getMask)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *img = from_Image(env, self);
	jobject jmask = NULL;

	if (img == NULL || img->mask == NULL)
		return NULL;

	fz_try(ctx)
		jmask = to_Image(ctx, env, img->mask);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jmask;
}

JNIEXPORT jobject JNICALL
FUN(Image_toPixmap)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *img = from_Image(env, self);
	fz_pixmap *pixmap = NULL;

	fz_try(ctx)
		pixmap = fz_get_pixmap_from_image(ctx, img, NULL, NULL, NULL, NULL);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Pixmap_safe(ctx, env, pixmap);
}

/* Outline interface */

JNIEXPORT void JNICALL
FUN(Outline_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_outline *outline = from_Outline(env, self);

	if (ctx == NULL || outline == NULL)
		return;

	fz_drop_outline(ctx, outline);
}

/* Annotation Interface */

JNIEXPORT void JNICALL
FUN(Annotation_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);

	if (ctx == NULL || annot == NULL)
		return;

	fz_drop_annot(ctx, annot);
}

JNIEXPORT void JNICALL
FUN(Annotation_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie= from_Cookie(env, jcookie);
	fz_device *dev = from_Device(env, jdev, ctx);
	fz_annot *annot = from_Annotation(env, self);
	NativeDeviceInfo *info;

	if (ctx == NULL || self == NULL || jdev == NULL)
		return;

	info = lockNativeDevice(env, jdev);
	fz_try(ctx)
		fz_run_annot(ctx, annot, dev, &ctm, cookie);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jlong JNICALL
FUN(Annotation_advance)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = NULL;

	if (ctx == NULL || self == NULL)
		return 0;

	fz_try(ctx)
	{
		annot = from_Annotation(env, self);
		annot = fz_next_annot(ctx, annot);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(annot);
}

/* Link interface */

JNIEXPORT void JNICALL
FUN(Link_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_link *link = from_Link(env, self);

	if (ctx == NULL || link == NULL)
		return;

	fz_drop_link(ctx, link);
}

/* Document interface */

JNIEXPORT void JNICALL
FUN(Document_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);

	if (ctx == NULL || doc == NULL)
		return;

	fz_drop_document(ctx, doc);
}

JNIEXPORT jlong JNICALL
FUN(Document_newNativeWithPath)(JNIEnv *env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	fz_document *document = NULL;
	const char *filename = NULL;

	if (ctx == NULL || jfilename == NULL)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (filename == NULL)
		return 0;

	fz_try(ctx)
		document = fz_open_document(ctx, filename);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(document);
}

JNIEXPORT jboolean JNICALL
FUN(Document_needsPassword)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	int okay = 0;

	if (ctx == NULL || document == NULL)
		return 0;

	fz_try(ctx)
		okay = fz_needs_password(ctx, document);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return okay;
}

JNIEXPORT jboolean JNICALL
FUN(Document_authenticatePassword)(JNIEnv *env, jobject self, jstring jpassword)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	const char *password = NULL;
	int okay = 0;

	if (ctx == NULL || document == NULL)
		return 0;

	if (jpassword == NULL)
		password = "";
	else
	{
		password = (*env)->GetStringUTFChars(env, jpassword, NULL);
		if (!password)
			return 0;
	}

	fz_try(ctx)
		okay = fz_authenticate_password(ctx, document, password);
	fz_always(ctx)
		if (jpassword != NULL)
			(*env)->ReleaseStringUTFChars(env, jpassword, password);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return okay;
}

JNIEXPORT jint JNICALL
FUN(Document_countPages)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	int count = 0;

	if (ctx == NULL || document == NULL)
		return 0;

	fz_try(ctx)
		count = fz_count_pages(ctx, document);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return count;
}

JNIEXPORT jobject JNICALL
FUN(Document_loadPage)(JNIEnv *env, jobject self, jint number)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	fz_page *page = NULL;

	if (ctx == NULL || document == NULL)
		return NULL;

	fz_try(ctx)
		page = fz_load_page(ctx, document, number);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Page_safe(ctx, env, page);
}

JNIEXPORT jobject JNICALL
FUN(Document_getMetaData)(JNIEnv *env, jobject self, jstring jkey)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	const char *ckey;
	char info[256];

	if (ctx == NULL || document == NULL)
		return NULL;

	ckey = (*env)->GetStringUTFChars(env, jkey, NULL);
	if (!ckey)
		return NULL;

	fz_try(ctx)
		fz_lookup_metadata(ctx, document, ckey, info, sizeof info);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jkey, ckey);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return (*env)->NewStringUTF(env, info);
}

JNIEXPORT jboolean JNICALL
FUN(Document_isUnencryptedPDF)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	pdf_document *idoc = pdf_specifics(ctx, document);
	int cryptVer;

	if (idoc == NULL)
		return JNI_FALSE; // Not a PDF

	cryptVer = pdf_crypt_version(ctx, idoc);
	return (cryptVer == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
FUN(Document_loadOutline)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *document = from_Document(env, self);
	fz_outline *outline = NULL;

	if (ctx == NULL || document == NULL)
		return NULL;

	fz_var(outline);

	fz_try(ctx)
		outline = fz_load_outline(ctx, document);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Outline_safe(ctx, env, outline);
}

/* Page interface */

JNIEXPORT void JNICALL
FUN(Page_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);

	if (ctx == NULL || page == NULL)
		return;

	fz_drop_page(ctx, page);
}

JNIEXPORT jobject JNICALL
FUN(Page_toPixmap)(JNIEnv *env, jobject self, jobject ctm_, jobject colorspace_, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_colorspace *colorspace = from_ColorSpace(env, colorspace_);
	fz_matrix ctm = from_Matrix(env, ctm_);

	fz_pixmap *pixmap = NULL;

	fz_try(ctx)
		pixmap = fz_new_pixmap_from_page(ctx, page, &ctm, colorspace, alpha);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return to_Pixmap_safe(ctx, env, pixmap);
}

JNIEXPORT jobject JNICALL
FUN(Page_getBounds)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	jobject jrect = NULL;
	fz_rect rect;

	if (ctx == NULL || page == NULL)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_page(ctx, page, &rect));
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jrect;
}

JNIEXPORT void JNICALL
FUN(Page_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	fz_device *dev = from_Device(env, jdev, ctx);
	fz_page *page = from_Page(env, self);
	NativeDeviceInfo *info;

	if (ctx == NULL || self == NULL || jdev == NULL)
		return;

	info = lockNativeDevice(env, jdev);
	fz_try(ctx)
		fz_run_page(ctx, page, dev, &ctm, cookie);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Page_runPageContents)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	fz_device *dev = from_Device(env, jdev, ctx);
	fz_page *page = from_Page(env, self);
	NativeDeviceInfo *info;

	if (ctx == NULL || page == NULL || dev == NULL)
		return;

	info = lockNativeDevice(env, jdev);
	fz_try(ctx)
		fz_run_page_contents(ctx, page, dev, &ctm, cookie);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jobject JNICALL
FUN(Page_getAnnotations)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_annot *annot = NULL;
	fz_annot *first = NULL;
	jobject jannots = NULL;
	int annot_count;
	int i;

	if (ctx == NULL || page == NULL)
		return NULL;

	fz_var(annot);
	fz_var(jannots);

	fz_try(ctx)
	{
		jannots = (*env)->GetObjectField(env, self, fid_Page_nativeAnnots);

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
				(*env)->SetObjectField(env, self, fid_Page_nativeAnnots, NULL);
			}
			break; /* No annotations! */
		}

		jannots = (*env)->NewObjectArray(env, annot_count, cls_Annot, NULL);
		if (jannots == NULL)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getAnnotations failed (1)");
		(*env)->SetObjectField(env, self, fid_Page_nativeAnnots, jannots);

		/* Now run through actually creating the annotation objects */
		annot = first;
		for (i = 0; annot != NULL && i < annot_count; i++)
		{
			jobject jannot = to_Annotation(ctx, env, annot);
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

/* Cookie interface */

JNIEXPORT void JNICALL
FUN(Cookie_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = from_Cookie(env, self);

	if (ctx == NULL || cookie == NULL)
		return;

	fz_free(ctx, cookie);
}

JNIEXPORT jlong JNICALL
FUN(Cookie_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		cookie = fz_malloc_struct(ctx, fz_cookie);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(cookie);
}

JNIEXPORT void JNICALL
FUN(Cookie_abort)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = from_Cookie(env, self);

	if (ctx == NULL || cookie == NULL)
		return;

	cookie->abort = 1;
}

/* DisplayList interface */

JNIEXPORT jlong JNICALL
FUN(DisplayList_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);

	fz_display_list *list = NULL;

	if (ctx == NULL)
		return 0;

	fz_try(ctx)
		list = fz_new_display_list(ctx, NULL);
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return jlong_cast(list);
}

JNIEXPORT void JNICALL
FUN(DisplayList_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jrect, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	fz_device *dev = from_Device(env, jdev, ctx);
	NativeDeviceInfo *info;
	fz_rect local_rect;
	fz_rect *rect = NULL;

	if (ctx == NULL || self == NULL || jdev == NULL || list == NULL)
		return;

	/* Use a scissor rectangle if one is supplied */
	if (jrect)
	{
		rect = &local_rect;
		local_rect = from_Rect(env, jrect);
	}

	info = lockNativeDevice(env, jdev);
	fz_try(ctx)
		fz_run_display_list(ctx, list, dev, &ctm, rect, cookie);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(DisplayList_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);

	if (ctx == NULL || list == NULL)
		return;

	fz_drop_display_list(ctx, list);
}
