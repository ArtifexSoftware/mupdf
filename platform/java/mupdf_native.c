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
static jclass cls_Buffer;
static jclass cls_ColorSpace;
static jclass cls_Cookie;
static jclass cls_Device;
static jclass cls_DisplayList;
static jclass cls_Document;
static jclass cls_DocumentWriter;
static jclass cls_Exception;
static jclass cls_Font;
static jclass cls_Image;
static jclass cls_IndexOutOfBoundsException;
static jclass cls_Link;
static jclass cls_Matrix;
static jclass cls_NativeDevice;
static jclass cls_NullPointerException;
static jclass cls_Object;
static jclass cls_OutOfMemoryError;
static jclass cls_Outline;
static jclass cls_Page;
static jclass cls_Path;
static jclass cls_PathWalker;
static jclass cls_PDFDocument;
static jclass cls_PDFGraftMap;
static jclass cls_PDFObject;
static jclass cls_Pixmap;
static jclass cls_Point;
static jclass cls_Rect;
static jclass cls_Shade;
static jclass cls_StrokeState;
static jclass cls_StructuredText;
static jclass cls_Text;
static jclass cls_TextBlock;
static jclass cls_TextChar;
static jclass cls_TextLine;
static jclass cls_TextSpan;
static jclass cls_TextWalker;
static jclass cls_TryLaterException;

static jfieldID fid_Annot_pointer;
static jfieldID fid_Buffer_pointer;
static jfieldID fid_ColorSpace_pointer;
static jfieldID fid_Cookie_pointer;
static jfieldID fid_Device_pointer;
static jfieldID fid_DisplayList_pointer;
static jfieldID fid_Document_pointer;
static jfieldID fid_DocumentWriter_pointer;
static jfieldID fid_Font_pointer;
static jfieldID fid_Image_pointer;
static jfieldID fid_Link_bounds;
static jfieldID fid_Link_page;
static jfieldID fid_Link_uri;
static jfieldID fid_Matrix_a;
static jfieldID fid_Matrix_b;
static jfieldID fid_Matrix_c;
static jfieldID fid_Matrix_d;
static jfieldID fid_Matrix_e;
static jfieldID fid_Matrix_f;
static jfieldID fid_NativeDevice_nativeInfo;
static jfieldID fid_NativeDevice_nativeResource;
static jfieldID fid_Page_pointer;
static jfieldID fid_Path_pointer;
static jfieldID fid_PDFDocument_pointer;
static jfieldID fid_PDFGraftMap_pointer;
static jfieldID fid_PDFObject_pointer;
static jfieldID fid_Pixmap_pointer;
static jfieldID fid_Rect_x0;
static jfieldID fid_Rect_x1;
static jfieldID fid_Rect_y0;
static jfieldID fid_Rect_y1;
static jfieldID fid_Shade_pointer;
static jfieldID fid_StrokeState_pointer;
static jfieldID fid_StructuredText_pointer;
static jfieldID fid_Text_pointer;
static jfieldID fid_TextBlock_bbox;
static jfieldID fid_TextBlock_lines;
static jfieldID fid_TextChar_bbox;
static jfieldID fid_TextChar_c;
static jfieldID fid_TextLine_bbox;
static jfieldID fid_TextLine_spans;
static jfieldID fid_TextSpan_bbox;
static jfieldID fid_TextSpan_chars;

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
static jmethodID mid_Device_init;
static jmethodID mid_Device_popClip;
static jmethodID mid_Device_strokePath;
static jmethodID mid_Device_strokeText;
static jmethodID mid_DisplayList_init;
static jmethodID mid_Document_init;
static jmethodID mid_Font_init;
static jmethodID mid_Image_init;
static jmethodID mid_Link_init;
static jmethodID mid_Matrix_init;
static jmethodID mid_Object_toString;
static jmethodID mid_Outline_init;
static jmethodID mid_Page_init;
static jmethodID mid_PathWalker_closePath;
static jmethodID mid_PathWalker_curveTo;
static jmethodID mid_PathWalker_lineTo;
static jmethodID mid_PathWalker_moveTo;
static jmethodID mid_Path_init;
static jmethodID mid_PDFDocument_init;
static jmethodID mid_PDFGraftMap_init;
static jmethodID mid_PDFObject_init;
static jmethodID mid_Pixmap_init;
static jmethodID mid_Point_init;
static jmethodID mid_Rect_init;
static jmethodID mid_Shade_init;
static jmethodID mid_StrokeState_init;
static jmethodID mid_StructuredText_init;
static jmethodID mid_Text_init;
static jmethodID mid_TextBlock_init;
static jmethodID mid_TextChar_init;
static jmethodID mid_TextLine_init;
static jmethodID mid_TextSpan_init;
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
		if (!(*env)->ExceptionCheck(env) && msg)
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
	if (!local)
	{
		LOGI("Failed to find class %s", name);
		*failed = 1;
		return NULL;
	}

	current_class = (*env)->NewGlobalRef(env, local);
	if (!current_class)
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

	if (*failed || !current_class)
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

	if (*failed || !current_class)
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

	if (*failed || !current_class)
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

	cls_Buffer = get_class(&err, env, PKG"Buffer");
	fid_Buffer_pointer = get_field(&err, env, "pointer", "J");

	cls_ColorSpace = get_class(&err, env, PKG"ColorSpace");
	fid_ColorSpace_pointer = get_field(&err, env, "pointer", "J");
	mid_ColorSpace_init = get_method(&err, env, "<init>", "(J)V");
	mid_ColorSpace_fromPointer = get_static_method(&err, env, "fromPointer", "(J)L"PKG"ColorSpace;");

	cls_Cookie = get_class(&err, env, PKG"Cookie");
	fid_Cookie_pointer = get_field(&err, env, "pointer", "J");

	cls_Device = get_class(&err, env, PKG"Device");
	fid_Device_pointer = get_field(&err, env, "pointer", "J");
	mid_Device_init = get_method(&err, env, "<init>", "(J)V");
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
	mid_DisplayList_init = get_method(&err, env, "<init>", "(J)V");

	cls_Document = get_class(&err, env, PKG"Document");
	fid_Document_pointer = get_field(&err, env, "pointer", "J");
	mid_Document_init = get_method(&err, env, "<init>", "(J)V");

	cls_DocumentWriter = get_class(&err, env, PKG"DocumentWriter");
	fid_DocumentWriter_pointer = get_field(&err, env, "pointer", "J");

	cls_Font = get_class(&err, env, PKG"Font");
	fid_Font_pointer = get_field(&err, env, "pointer", "J");
	mid_Font_init = get_method(&err, env, "<init>", "(J)V");

	cls_Image = get_class(&err, env, PKG"Image");
	fid_Image_pointer = get_field(&err, env, "pointer", "J");
	mid_Image_init = get_method(&err, env, "<init>", "(J)V");

	cls_Link = get_class(&err, env, PKG"Link");
	fid_Link_bounds = get_field(&err, env, "bounds", "L"PKG"Rect;");
	fid_Link_page = get_field(&err, env, "page", "I");
	fid_Link_uri = get_field(&err, env, "uri", "Ljava/lang/String;");
	mid_Link_init = get_method(&err, env, "<init>", "(L"PKG"Rect;ILjava/lang/String;)V");

	cls_Matrix = get_class(&err, env, PKG"Matrix");
	fid_Matrix_a = get_field(&err, env, "a", "F");
	fid_Matrix_b = get_field(&err, env, "b", "F");
	fid_Matrix_c = get_field(&err, env, "c", "F");
	fid_Matrix_d = get_field(&err, env, "d", "F");
	fid_Matrix_e = get_field(&err, env, "e", "F");
	fid_Matrix_f = get_field(&err, env, "f", "F");
	mid_Matrix_init = get_method(&err, env, "<init>", "(FFFFFF)V");

	cls_Outline = get_class(&err, env, PKG"Outline");
	mid_Outline_init = get_method(&err, env, "<init>", "(Ljava/lang/String;ILjava/lang/String;[L"PKG"Outline;)V");

	cls_Page = get_class(&err, env, PKG"Page");
	fid_Page_pointer = get_field(&err, env, "pointer", "J");
	mid_Page_init = get_method(&err, env, "<init>", "(J)V");

	cls_Path = get_class(&err, env, PKG"Path");
	fid_Path_pointer = get_field(&err, env, "pointer", "J");
	mid_Path_init = get_method(&err, env, "<init>", "(J)V");

	cls_PDFDocument = get_class(&err, env, PKG"PDFDocument");
	fid_PDFDocument_pointer = get_field(&err, env, "pointer", "J");
	mid_PDFDocument_init = get_method(&err, env, "<init>", "(J)V");

	cls_PDFGraftMap = get_class(&err, env, PKG"PDFGraftMap");
	fid_PDFGraftMap_pointer = get_field(&err, env, "pointer", "J");
	mid_PDFGraftMap_init = get_method(&err, env, "<init>", "(J)V");

	cls_PDFObject = get_class(&err, env, PKG"PDFObject");
	fid_PDFObject_pointer = get_field(&err, env, "pointer", "J");
	mid_PDFObject_init = get_method(&err, env, "<init>", "(J)V");

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

	cls_StructuredText = get_class(&err, env, PKG"StructuredText");
	fid_StructuredText_pointer = get_field(&err, env, "pointer", "J");
	mid_StructuredText_init = get_method(&err, env, "<init>", "(J)V");

	cls_Text = get_class(&err, env, PKG"Text");
	fid_Text_pointer = get_field(&err, env, "pointer", "J");
	mid_Text_init = get_method(&err, env, "<init>", "(J)V");

	cls_TextBlock = get_class(&err, env, PKG"StructuredText$TextBlock");
	mid_TextBlock_init = get_method(&err, env, "<init>", "(L"PKG"StructuredText;)V");
	fid_TextBlock_bbox = get_field(&err, env, "bbox", "L"PKG"Rect;");
	fid_TextBlock_lines = get_field(&err, env, "lines", "[L"PKG"StructuredText$TextLine;");

	cls_TextChar = get_class(&err, env, PKG"StructuredText$TextChar");
	mid_TextChar_init = get_method(&err, env, "<init>", "(L"PKG"StructuredText;)V");
	fid_TextChar_bbox = get_field(&err, env, "bbox", "L"PKG"Rect;");
	fid_TextChar_c = get_field(&err, env, "c", "I");

	cls_TextLine = get_class(&err, env, PKG"StructuredText$TextLine");
	mid_TextLine_init = get_method(&err, env, "<init>", "(L"PKG"StructuredText;)V");
	fid_TextLine_bbox = get_field(&err, env, "bbox", "L"PKG"Rect;");
	fid_TextLine_spans = get_field(&err, env, "spans", "[L"PKG"StructuredText$TextSpan;");

	cls_TextSpan = get_class(&err, env, PKG"StructuredText$TextSpan");
	mid_TextSpan_init = get_method(&err, env, "<init>", "(L"PKG"StructuredText;)V");
	fid_TextSpan_bbox = get_field(&err, env, "bbox", "L"PKG"Rect;");
	fid_TextSpan_chars = get_field(&err, env, "chars", "[L"PKG"StructuredText$TextChar;");

	cls_TextWalker = get_class(&err, env, PKG"TextWalker");
	mid_TextWalker_showGlyph = get_method(&err, env, "showGlyph", "(L"PKG"Font;L"PKG"Matrix;IIZ)V");

	cls_TryLaterException = get_class(&err, env, PKG"TryLaterException");

	/* Standard Java classes */

	cls_Object = get_class(&err, env, "java/lang/Object");
	mid_Object_toString = get_method(&err, env, "toString", "()Ljava/lang/String;");

	cls_Exception = get_class(&err, env, "java/lang/Exception");
	cls_IndexOutOfBoundsException = get_class(&err, env, "java/lang/IndexOutOfBoundsException");
	cls_NullPointerException = get_class(&err, env, "java/lang/NullPointerException");

	cls_OutOfMemoryError = get_class(&err, env, "java/lang/OutOfMemoryError");

	return err;
}

static void lose_fids(JNIEnv *env)
{
	(*env)->DeleteGlobalRef(env, cls_Annot);
	(*env)->DeleteGlobalRef(env, cls_Buffer);
	(*env)->DeleteGlobalRef(env, cls_ColorSpace);
	(*env)->DeleteGlobalRef(env, cls_Cookie);
	(*env)->DeleteGlobalRef(env, cls_Device);
	(*env)->DeleteGlobalRef(env, cls_DisplayList);
	(*env)->DeleteGlobalRef(env, cls_Document);
	(*env)->DeleteGlobalRef(env, cls_DocumentWriter);
	(*env)->DeleteGlobalRef(env, cls_Exception);
	(*env)->DeleteGlobalRef(env, cls_Font);
	(*env)->DeleteGlobalRef(env, cls_Image);
	(*env)->DeleteGlobalRef(env, cls_IndexOutOfBoundsException);
	(*env)->DeleteGlobalRef(env, cls_Link);
	(*env)->DeleteGlobalRef(env, cls_Matrix);
	(*env)->DeleteGlobalRef(env, cls_NativeDevice);
	(*env)->DeleteGlobalRef(env, cls_NullPointerException);
	(*env)->DeleteGlobalRef(env, cls_Object);
	(*env)->DeleteGlobalRef(env, cls_OutOfMemoryError);
	(*env)->DeleteGlobalRef(env, cls_Outline);
	(*env)->DeleteGlobalRef(env, cls_Page);
	(*env)->DeleteGlobalRef(env, cls_Path);
	(*env)->DeleteGlobalRef(env, cls_PathWalker);
	(*env)->DeleteGlobalRef(env, cls_PDFDocument);
	(*env)->DeleteGlobalRef(env, cls_PDFGraftMap);
	(*env)->DeleteGlobalRef(env, cls_PDFObject);
	(*env)->DeleteGlobalRef(env, cls_Pixmap);
	(*env)->DeleteGlobalRef(env, cls_Point);
	(*env)->DeleteGlobalRef(env, cls_Rect);
	(*env)->DeleteGlobalRef(env, cls_Shade);
	(*env)->DeleteGlobalRef(env, cls_StrokeState);
	(*env)->DeleteGlobalRef(env, cls_StructuredText);
	(*env)->DeleteGlobalRef(env, cls_Text);
	(*env)->DeleteGlobalRef(env, cls_TextBlock);
	(*env)->DeleteGlobalRef(env, cls_TextChar);
	(*env)->DeleteGlobalRef(env, cls_TextLine);
	(*env)->DeleteGlobalRef(env, cls_TextSpan);
	(*env)->DeleteGlobalRef(env, cls_TextWalker);
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
	if (!base_context)
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

	if (ctx)
		return ctx;

	ctx = fz_clone_context(base_context);
	if (!ctx)
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

	if (!ctx)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Matrix, mid_Matrix_init, mat->a, mat->b, mat->c, mat->d, mat->e, mat->f);
	if (!jobj)
		fz_throw_java(ctx, env);

	return jobj;
}

static inline jobject to_Rect(fz_context *ctx, JNIEnv *env, const fz_rect *rect)
{
	jobject jobj;

	if (!ctx)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Rect, mid_Rect_init, rect->x0, rect->y0, rect->x1, rect->y1);
	if (!jobj)
		fz_throw_java(ctx, env);

	return jobj;
}

static inline jobject to_Point(fz_context *ctx, JNIEnv *env, fz_point point)
{
	jobject jpoint;

	if (!ctx)
		return NULL;

	jpoint = (*env)->NewObject(env, cls_Point, mid_Point_init, point.x, point.y);
	if (!jpoint)
		fz_throw_java(ctx, env);

	return jpoint;
}

static inline jfloatArray to_jfloatArray(fz_context *ctx, JNIEnv *env, const float *color, jint n)
{
	jfloatArray arr;

	if (!ctx)
		return NULL;

	arr = (*env)->NewFloatArray(env, n);
	if (!arr)
		fz_throw_java(ctx, env);

	(*env)->SetFloatArrayRegion(env, arr, 0, n, color);

	return arr;
}

static inline jobject to_Annotation(fz_context *ctx, JNIEnv *env, fz_annot *annot)
{
	jobject jannot;

	if (!ctx || !annot)
		return NULL;

	jannot = (*env)->NewObject(env, cls_Annot, mid_Annot_init, jlong_cast(annot));
	if (!jannot)
		fz_throw_java(ctx, env);

	fz_keep_annot(ctx, annot);

	return jannot;
}

static inline jobject to_ColorSpace(fz_context *ctx, JNIEnv *env, fz_colorspace *cs)
{
	jobject jobj;

	if (!ctx || !cs)
		return NULL;

	jobj = (*env)->CallStaticObjectMethod(env, cls_ColorSpace, mid_ColorSpace_fromPointer, jlong_cast(cs));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_colorspace(ctx, cs);

	return jobj;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Device_safe_own(fz_context *ctx, JNIEnv *env, fz_device *device)
{
	jobject jdev;

	if (!ctx || !device)
		return NULL;

	jdev = (*env)->NewObject(env, cls_DisplayList, mid_Device_init, jlong_cast(device));
	if (!jdev)
	{
		fz_drop_device(ctx, device);
		return NULL;
	}

	return jdev;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_DisplayList_safe_own(fz_context *ctx, JNIEnv *env, fz_display_list *list)
{
	jobject jlist;

	if (!ctx || !list)
		return NULL;

	jlist = (*env)->NewObject(env, cls_DisplayList, mid_DisplayList_init, jlong_cast(list));
	if (!jlist)
	{
		fz_drop_display_list(ctx, list);
		return NULL;
	}

	return jlist;
}

/* don't throw fitz exceptions */
static inline jobject to_Font_safe(fz_context *ctx, JNIEnv *env, fz_font *font)
{
	jobject jfont;

	if (!ctx || !font)
		return NULL;

	jfont = (*env)->NewObject(env, cls_Font, mid_Font_init, jlong_cast(font));
	if (jfont)
		fz_keep_font(ctx, font);

	return jfont;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_PDFGraftMap_safe_own(fz_context *ctx, JNIEnv *env, jobject pdf, pdf_graft_map *map)
{
	jobject jmap;

	if (!ctx || !map || !pdf)
		return NULL;

	jmap = (*env)->NewObject(env, cls_PDFGraftMap, mid_PDFGraftMap_init, jlong_cast(map), pdf);
	if (!jmap)
	{
		pdf_drop_graft_map(ctx, map);
		return NULL;
	}

	return jmap;
}

static inline jobject to_Image(fz_context *ctx, JNIEnv *env, fz_image *img)
{
	jobject jobj;

	if (!ctx || !img)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Image, mid_Image_init, jlong_cast(img));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_image(ctx, img);

	return jobj;
}

/* don't throw fitz exceptions */
static inline jobject to_Outline_safe(fz_context *ctx, JNIEnv *env, fz_outline *outline)
{
	jobject joutline = NULL;
	jobject jarr = NULL;
	jsize jindex = 0;
	jsize count = 0;
	fz_outline *counter = outline;

	if (!ctx || !outline)
		return NULL;

	while (counter)
	{
		count++;
		counter = counter->next;
	}

	jarr = (*env)->NewObjectArray(env, count, cls_Outline, NULL);
	if (!jarr)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "loadOutline failed (1)");
		return NULL;
	}

	while (outline)
	{
		jstring jtitle = NULL;
		jint jpage = 0;
		jstring juri = NULL;
		jobject jdown = NULL;

		if (outline->title)
			jtitle = (*env)->NewStringUTF(env, outline->title);

		if (outline->dest.kind == FZ_LINK_GOTO)
			jpage = outline->dest.ld.gotor.page;
		else if (outline->dest.kind == FZ_LINK_URI)
			juri = (*env)->NewStringUTF(env, outline->dest.ld.uri.uri);

		if (outline->down)
		{
			jdown = to_Outline_safe(ctx, env, outline->down);
			if (!jdown)
			{
				jni_throw(env, FZ_ERROR_GENERIC, "loadOutline failed (2)");
				return NULL;
			}
		}

		joutline = (*env)->NewObject(env, cls_Outline, mid_Outline_init, jtitle, jpage, juri, jdown);
		if (!joutline)
		{
			jni_throw(env, FZ_ERROR_GENERIC, "loadOutline failed (3)");
			return NULL;
		}
		if (jdown)
			(*env)->DeleteLocalRef(env, jdown);
		if (juri)
			(*env)->DeleteLocalRef(env, juri);
		if (jtitle)
			(*env)->DeleteLocalRef(env, jtitle);

		(*env)->SetObjectArrayElement(env, jarr, jindex++, joutline);
		(*env)->DeleteLocalRef(env, joutline);
		outline = outline->next;
	}

	return jarr;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Page_safe_own(fz_context *ctx, JNIEnv *env, fz_page *page)
{
	jobject jobj;

	if (!ctx || !page)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Page, mid_Page_init, jlong_cast(page));
	if (!jobj)
	{
		fz_drop_page(ctx, page);
		return NULL;
	}

	return jobj;
}

static inline jobject to_Path(fz_context *ctx, JNIEnv *env, const fz_path *path)
{
	jobject jobj;

	if (!ctx || !path)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Path, mid_Path_init, jlong_cast(path));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_path(ctx, path);

	return jobj;
}

/* don't throw fitz exceptions */
static inline jobject to_Document_safe(fz_context *ctx, JNIEnv *env, fz_document *doc)
{
	jobject jdoc;

	if (!ctx || !doc)
		return NULL;

	jdoc = (*env)->NewObject(env, cls_Document, mid_Document_init, jlong_cast(doc));
	if (jdoc)
		fz_keep_document(ctx, doc);

	return jdoc;
}

/* don't throw fitz exceptions */
static inline jobject to_PDFDocument_safe(fz_context *ctx, JNIEnv *env, pdf_document *pdf)
{
	jobject jpdf;

	if (!ctx || !pdf)
		return NULL;

	jpdf = (*env)->NewObject(env, cls_PDFDocument, mid_PDFDocument_init, jlong_cast(pdf));
	if (jpdf)
		fz_keep_document(ctx, (fz_document *) pdf);

	return jpdf;
}

/* don't throw fitz exceptions */
static inline jobject to_PDFObject_safe(fz_context *ctx, JNIEnv *env, jobject pdf, pdf_obj *obj)
{
	jobject jobj;

	if (!ctx || !obj || !pdf)
		return NULL;

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), pdf);
	if (jobj)
		pdf_keep_obj(ctx, obj);

	return jobj;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_PDFObject_safe_own(fz_context *ctx, JNIEnv *env, jobject pdf, pdf_obj *obj)
{
	jobject jobj;

	if (!ctx || !obj || !pdf)
		return NULL;

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), pdf);
	if (!jobj)
	{
		pdf_drop_obj(ctx, obj);
		return NULL;
	}

	return jobj;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_Pixmap_safe_own(fz_context *ctx, JNIEnv *env, fz_pixmap *pixmap)
{
	jobject jobj;

	if (!ctx || !pixmap)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Pixmap, mid_Pixmap_init, jlong_cast(pixmap));
	if (!jobj)
	{
		fz_drop_pixmap(ctx, pixmap);
		return NULL;
	}

	return jobj;
}

static inline jobject to_Shade(fz_context *ctx, JNIEnv *env, fz_shade *shd)
{
	jobject jobj;

	if (!ctx || !shd)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Shade, mid_Shade_init, jlong_cast(shd));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_shade(ctx, shd);

	return jobj;
}

static inline jobject to_StrokeState(fz_context *ctx, JNIEnv *env, const fz_stroke_state *state)
{
	jobject jobj;

	if (!ctx || !state)
		return NULL;

	jobj = (*env)->NewObject(env, cls_StrokeState, mid_StrokeState_init, jlong_cast(state));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_stroke_state(ctx, state);

	return jobj;
}

/* take ownership and don't throw fitz exceptions */
static inline jobject to_StructuredText_safe_own(fz_context *ctx, JNIEnv *env, fz_stext_page *text)
{
	jobject jtext;

	if (!ctx || !text)
		return NULL;

	jtext = (*env)->NewObject(env, cls_StructuredText, mid_StructuredText_init, jlong_cast(text));
	if (!jtext)
	{
		fz_drop_stext_page(ctx, text);
		return NULL;
	}

	return jtext;
}

static inline jobject to_Text(fz_context *ctx, JNIEnv *env, const fz_text *text)
{
	jobject jobj;

	if (!ctx)
		return NULL;

	jobj = (*env)->NewObject(env, cls_Text, mid_Text_init, jlong_cast(text));
	if (!jobj)
		fz_throw_java(ctx, env);

	fz_keep_text(ctx, text);

	return jobj;
}

/* Conversion functions: Java to C. These all throw java exceptions. */

static inline fz_matrix from_Matrix(JNIEnv *env, jobject jmat)
{
	fz_matrix mat;

	if (!jmat)
		return fz_identity;

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

	if (!jrect)
		return fz_empty_rect;

	rect.x0 = (*env)->GetFloatField(env, jrect, fid_Rect_x0);
	rect.x1 = (*env)->GetFloatField(env, jrect, fid_Rect_x1);
	rect.y0 = (*env)->GetFloatField(env, jrect, fid_Rect_y0);
	rect.y1 = (*env)->GetFloatField(env, jrect, fid_Rect_y1);

	return rect;
}

static inline void from_jfloatArray(JNIEnv *env, float *color, jint n, jfloatArray jcolor)
{
	jsize len;

	if (!jcolor)
		len = 0;
	else
	{
		len = (*env)->GetArrayLength(env, jcolor);
		if (len > n)
			len = n;
		(*env)->GetFloatArrayRegion(env, jcolor, 0, len, color);
	}

	if (len < n)
		memset(color+len, 0, (n - len) * sizeof(float));
}

static inline fz_annot *from_Annotation(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_annot *, (*env)->GetLongField(env, jobj, fid_Annot_pointer));
}

static inline fz_buffer *from_Buffer(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_buffer *, (*env)->GetLongField(env, jobj, fid_Buffer_pointer));
}

static inline fz_cookie *from_Cookie(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_cookie *, (*env)->GetLongField(env, jobj, fid_Cookie_pointer));
}

static inline fz_colorspace *from_ColorSpace(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_colorspace *, (*env)->GetLongField(env, jobj, fid_ColorSpace_pointer));
}

static fz_device *from_Device(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_device *, (*env)->GetLongField(env, jobj, fid_Device_pointer));
}

static inline fz_display_list *from_DisplayList(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_display_list *, (*env)->GetLongField(env, jobj, fid_DisplayList_pointer));
}

static inline fz_document *from_Document(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_document *, (*env)->GetLongField(env, jobj, fid_Document_pointer));
}

static inline fz_document_writer *from_DocumentWriter(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_document_writer *, (*env)->GetLongField(env, jobj, fid_DocumentWriter_pointer));
}

static inline pdf_document *from_PDFDocument(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(pdf_document *, (*env)->GetLongField(env, jobj, fid_PDFDocument_pointer));
}

static inline pdf_graft_map *from_PDFGraftMap(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(pdf_graft_map *, (*env)->GetLongField(env, jobj, fid_PDFGraftMap_pointer));
}

static inline pdf_obj *from_PDFObject(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(pdf_obj *, (*env)->GetLongField(env, jobj, fid_PDFObject_pointer));
}

static inline fz_font *from_Font(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_font *, (*env)->GetLongField(env, jobj, fid_Font_pointer));
}

static inline fz_image *from_Image(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_image *, (*env)->GetLongField(env, jobj, fid_Image_pointer));
}

static inline fz_page *from_Page(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_page *, (*env)->GetLongField(env, jobj, fid_Page_pointer));
}

static inline fz_path *from_Path(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_path *, (*env)->GetLongField(env, jobj, fid_Path_pointer));
}

static inline fz_pixmap *from_Pixmap(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_pixmap *, (*env)->GetLongField(env, jobj, fid_Pixmap_pointer));
}

static inline fz_shade *from_Shade(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_shade *, (*env)->GetLongField(env, jobj, fid_Shade_pointer));
}

static inline fz_stroke_state *from_StrokeState(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_stroke_state *, (*env)->GetLongField(env, jobj, fid_StrokeState_pointer));
}

static inline fz_stext_page *from_StructuredText(JNIEnv *env, jobject jobj)
{
	if (!jobj)
		return NULL;
	return CAST(fz_stext_page *, (*env)->GetLongField(env, jobj, fid_StructuredText_pointer));
}

static inline fz_text *from_Text(JNIEnv *env, jobject jobj)
{
	if (!jobj)
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
		return NULL;
	}

	return (fz_device*)dev;
}

JNIEXPORT jlong JNICALL
FUN(Device_newNative)(JNIEnv *env, jclass self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		dev = fz_new_java_device(ctx, env, self);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(dev);
}

JNIEXPORT void JNICALL
FUN(Device_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);

	if (!ctx || !dev)
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
	if (!info)
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
	if (info)
		info->unlock(env, info);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *ninfo;

	if (!ctx || !dev)
		return;

	FUN(Device_finalize)(env, self); /* Call super.finalize() */

	ninfo = CAST(NativeDeviceInfo *, (*env)->GetLongField(env, self, fid_NativeDevice_nativeInfo));
	if (ninfo)
	{
		fz_drop_pixmap(ctx, ninfo->pixmap);
		fz_free(ctx, ninfo);
	}
}

JNIEXPORT void JNICALL
FUN(NativeDevice_close)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
FUN(NativeDevice_fillPath)(JNIEnv *env, jobject self, jobject jpath, jboolean even_odd, jobject jctm, jobject jcs, jfloatArray jcolor, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !path || !cs)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_path(ctx, dev, path, even_odd, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_strokePath)(JNIEnv *env, jobject self, jobject jpath, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_path *path = from_Path(env, jpath);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !path || !stroke || !cs)
		return;

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
	fz_device *dev = from_Device(env, self);
	fz_path *path = from_Path(env, jpath);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !path)
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
	fz_device *dev = from_Device(env, self);
	fz_path *path = from_Path(env, jpath);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !path || !stroke)
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
FUN(NativeDevice_fillText)(JNIEnv *env, jobject self, jobject jtext, jobject jctm, jobject jcs, jfloatArray jcolor, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !text || !cs)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_text(ctx, dev, text, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_strokeText)(JNIEnv *env, jobject self, jobject jtext, jobject jstroke, jobject jctm, jobject jcs, jfloatArray jcolor, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_text *text = from_Text(env, jtext);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !text || !stroke || !cs)
		return;

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
	fz_device *dev = from_Device(env, self);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
	fz_device *dev = from_Device(env, self);
	fz_text *text = from_Text(env, jtext);
	fz_stroke_state *stroke = from_StrokeState(env, jstroke);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !text || !stroke)
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
	fz_device *dev = from_Device(env, self);
	fz_text *text = from_Text(env, jtext);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !text)
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
FUN(NativeDevice_fillShade)(JNIEnv *env, jobject self, jobject jshd, jobject jctm, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_shade *shd = from_Shade(env, jshd);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !shd)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_shade(ctx, dev, shd, &ctm, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillImage)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_image *img = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !img)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_image(ctx, dev, img, &ctm, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_fillImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jctm, jobject jcs, jfloatArray jcolor, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_image *img = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !img || !cs)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_fill_image_mask(ctx, dev, img, &ctm, cs, color, alpha);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_clipImageMask)(JNIEnv *env, jobject self, jobject jimg, jobject jctm)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_image *img = from_Image(env, jimg);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;

	if (!ctx || !dev || !img)
		return;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		fz_clip_image_mask(ctx, dev, img, &ctm, NULL);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(NativeDevice_popClip)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
	fz_device *dev = from_Device(env, self);
	fz_rect rect = from_Rect(env, jrect);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	float color[FZ_MAX_COLORS];
	NativeDeviceInfo *info;

	from_jfloatArray(env, color, cs ? cs->n : FZ_MAX_COLORS, jcolor);

	if (!ctx || !dev || !cs)
		return;

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
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
FUN(NativeDevice_beginGroup)(JNIEnv *env, jobject self, jobject jrect, jboolean isolated, jboolean knockout, jint blendmode, jfloat alpha)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_rect rect = from_Rect(env, jrect);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
FUN(NativeDevice_beginTile)(JNIEnv *env, jobject self, jobject jarea, jobject jview, jfloat xstep, jfloat ystep, jobject jctm, jint id)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	fz_rect area = from_Rect(env, jarea);
	fz_rect view = from_Rect(env, jview);
	fz_matrix ctm = from_Matrix(env, jctm);
	NativeDeviceInfo *info;
	int i = 0;

	if (!ctx || !dev)
		return 0;

	info = lockNativeDevice(env, self);
	fz_try(ctx)
		i = fz_begin_tile_id(ctx, dev, &area, &view, xstep, ystep, &ctm, id);
	fz_always(ctx)
		unlockNativeDevice(env, info);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return i;
}

JNIEXPORT void JNICALL
FUN(NativeDevice_endTile)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_device *dev = from_Device(env, self);
	NativeDeviceInfo *info;

	if (!ctx || !dev)
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
FUN(DrawDevice_newNative)(JNIEnv *env, jclass self, jobject jpixmap)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, jpixmap);
	fz_device *device = NULL;

	if (!ctx || !pixmap)
		return 0;

	fz_try(ctx)
		device = fz_new_draw_device(ctx, NULL, pixmap);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(device);
}

JNIEXPORT jlong JNICALL
FUN(DisplayListDevice_newNative)(JNIEnv *env, jclass self, jobject jlist)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, jlist);
	fz_device *device = NULL;

	if (!ctx || !list)
		return 0;

	fz_var(device);

	fz_try(ctx)
		device = fz_new_list_device(ctx, list);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

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

	if (!ctx)
		return 0;

	fz_var(pixmap);
	fz_var(ninfo);

	fz_try(ctx)
	{
//		LOGI("DrawDeviceNative: bitmap=%d,%d page=%d,%d->%d,%d patch=%d,%d->%d,%d", width, height, pageX0, pageY0, pageX1, pageY1, patchX0, patchY0, patchX1, patchY1);
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
		return 0;
	}

	return jlong_cast(device);
}

static void androidDrawDevice_lock(JNIEnv *env, NativeDeviceInfo *info)
{
	uint8_t *pixels;

	assert(info);
	assert(info->object);

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
	assert(info);
	assert(info->object);

	if (AndroidBitmap_unlockPixels(env, info->object) < 0)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Bitmap unlock failed in DrawDevice call");
	}
}

JNIEXPORT jlong JNICALL
FUN(android_AndroidDrawDevice_newNative)(JNIEnv *env, jclass self, jobject jbitmap, jint pageX0, jint pageY0, jint pageX1, jint pageY1, jint patchX0, jint patchY0, jint patchX1, jint patchY1)
{
	fz_context *ctx = get_context(env);
	AndroidBitmapInfo info;
	jlong device = 0;
	int ret;

	if (!ctx || !jbitmap)
		return 0;

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
		return 0;
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

	if (!ctx || !jbitmap)
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
		fz_drop_pixmap(ctx, pixmap);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
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
	if (!ctx || !cs)
		return;
	fz_drop_colorspace(ctx, cs);
}

JNIEXPORT jint JNICALL
FUN(ColorSpace_getNumberOfComponents)(JNIEnv *env, jobject self)
{
	fz_colorspace *cs = from_ColorSpace(env, self);
	if (!cs)
		return 0;
	return cs->n;
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceGray)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	if (!ctx)
		return 0;
	return jlong_cast(fz_device_gray(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceRGB)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	if (!ctx)
		return 0;
	return jlong_cast(fz_device_rgb(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceBGR)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	if (!ctx)
		return 0;
	return jlong_cast(fz_device_bgr(ctx));
}

JNIEXPORT jlong JNICALL
FUN(ColorSpace_nativeDeviceCMYK)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	if (!ctx)
		return 0;
	return jlong_cast(fz_device_cmyk(ctx));
}

/* Font interface */

JNIEXPORT void JNICALL
FUN(Font_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);

	if (!ctx || !font)
		return;

	fz_drop_font(ctx, font);
}

JNIEXPORT jlong JNICALL
FUN(Font_newNative)(JNIEnv *env, jobject self, jstring jname, jint index)
{
	fz_context *ctx = get_context(env);
	const char *name = NULL;
	fz_font *font = NULL;

	if (!ctx || !jname)
		return 0;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Font constructor failed");
		return 0;
	}

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
		if (name)
			(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(font);
}

JNIEXPORT jstring JNICALL
FUN(Font_getName)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);

	if (!ctx || !font)
		return NULL;

	return (*env)->NewStringUTF(env, font->name);
}

JNIEXPORT jint JNICALL
FUN(Font_encodeCharacter)(JNIEnv *env, jobject self, jint unicode)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);
	jint glyph = 0;

	if (!ctx || !font)
		return 0;

	fz_try(ctx)
		glyph = fz_encode_character(ctx, font, unicode);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return glyph;
}

JNIEXPORT jfloat JNICALL
FUN(Font_advanceGlyph)(JNIEnv *env, jobject self, jint glyph, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_font *font = from_Font(env, self);
	float advance = 0;

	if (!ctx || !font)
		return 0;

	fz_try(ctx)
		advance = fz_advance_glyph(ctx, font, glyph, wmode);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return advance;
}

/* Pixmap Interface */

JNIEXPORT void JNICALL
FUN(Pixmap_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (!ctx || !pixmap)
		return;

	fz_drop_pixmap(ctx, pixmap);
}

JNIEXPORT jlong JNICALL
FUN(Pixmap_newNative)(JNIEnv *env, jobject self, jobject jcs, jint x, jint y, jint w, jint h, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_pixmap *pixmap = NULL;

	if (!ctx || !cs)
		return 0;

	fz_try(ctx)
	{
		pixmap = fz_new_pixmap(ctx, cs, w, h, alpha);
		pixmap->x = x;
		pixmap->y = y;
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(pixmap);
}

JNIEXPORT void JNICALL
FUN(Pixmap_clear)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (!ctx || !pixmap)
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

	if (!ctx || !pixmap)
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
	if (!ctx || !pixmap)
		return 0;
	return pixmap->x;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getY)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return 0;
	return pixmap->y;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getWidth)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return 0;
	return pixmap->w;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getHeight)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return 0;
	return pixmap->h;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getNumberOfComponents)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return 0;
	return pixmap->n;
}

JNIEXPORT jboolean JNICALL
FUN(Pixmap_getAlpha)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return JNI_FALSE;
	return pixmap->alpha ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getStride)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	if (!ctx || !pixmap)
		return 0;
	return pixmap->stride;
}

JNIEXPORT jobject JNICALL
FUN(Pixmap_getColorSpace)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	jobject jcs = NULL;

	if (!ctx || !pixmap)
		return NULL;

	fz_try(ctx)
	{
		fz_colorspace *cs = fz_pixmap_colorspace(ctx, pixmap);
		jcs = to_ColorSpace(ctx, env, cs);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jcs;
}

JNIEXPORT jbyteArray JNICALL
FUN(Pixmap_getSamples)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	int size = pixmap->h * pixmap->stride;
	jbyteArray arr;

	if (!ctx || !pixmap)
		return NULL;

	arr = (*env)->NewByteArray(env, size);
	if (!arr)
		return NULL;

	(*env)->SetByteArrayRegion(env, arr, 0, size, (const jbyte *)pixmap->samples);

	return arr;
}

JNIEXPORT jbyte JNICALL
FUN(Pixmap_getSample)(JNIEnv *env, jobject self, jint x, jint y, jint k)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (!ctx || !pixmap)
		return 0;

	if (x < 0 || x >= pixmap->w)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "X out of range");
		return 0;
	}
	if (y < 0 || y >= pixmap->h)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Y out of range");
		return 0;
	}
	if (k < 0 || k >= pixmap->n)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "K out of range");
		return 0;
	}

	return pixmap->samples[(x + y * pixmap->w) * pixmap->n + k];
}

JNIEXPORT jintArray JNICALL
FUN(Pixmap_getPixels)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);
	int size = pixmap->w * pixmap->h;
	jintArray arr;

	if (!ctx || !pixmap)
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

	arr = (*env)->NewIntArray(env, size);
	if (!arr)
		return NULL;

	(*env)->SetIntArrayRegion(env, arr, 0, size, (const jint *)pixmap->samples);

	return arr;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getXResolution)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (!ctx || !pixmap)
		return 0;

	return pixmap->xres;
}

JNIEXPORT jint JNICALL
FUN(Pixmap_getYResolution)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, self);

	if (!ctx || !pixmap)
		return 0;

	return pixmap->yres;
}

/* Path Interface */

JNIEXPORT void JNICALL
FUN(Path_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_drop_path(ctx, path);
}

JNIEXPORT jlong JNICALL
FUN(Path_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		path = fz_new_path(ctx);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(path);
}

JNIEXPORT jobject JNICALL
FUN(Path_currentPoint)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);
	jobject jpoint = NULL;

	if (!ctx || !path)
		return NULL;

	fz_try(ctx)
		jpoint = to_Point(ctx, env, fz_currentpoint(ctx, path));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jpoint;
}

JNIEXPORT void JNICALL
FUN(Path_moveTo)(JNIEnv *env, jobject self, jfloat x, jfloat y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_moveto(ctx, path, x, y);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_lineTo)(JNIEnv *env, jobject self, jfloat x, jfloat y)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_lineto(ctx, path, x, y);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveTo)(JNIEnv *env, jobject self, jfloat cx1, jfloat cy1, jfloat cx2, jfloat cy2, jfloat ex, jfloat ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_curveto(ctx, path, cx1, cy1, cx2, cy2, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveToV)(JNIEnv *env, jobject self, jfloat cx, jfloat cy, jfloat ex, jfloat ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_curvetov(ctx, path, cx, cy, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_curveToY)(JNIEnv *env, jobject self, jfloat cx, jfloat cy, jfloat ex, jfloat ey)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_curvetoy(ctx, path, cx, cy, ex, ey);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_rect)(JNIEnv *env, jobject self, jint x1, jint y1, jint x2, jint y2)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
		return;

	fz_try(ctx)
		fz_rectto(ctx, path, x1, y1, x2, y2);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Path_closePath)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_path *path = from_Path(env, self);

	if (!ctx || !path)
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

	if (!ctx || !path)
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

	if (!ctx || !old_path)
		return 0;

	fz_try(ctx)
		new_path = fz_clone_path(ctx, old_path);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

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

	if (!ctx || !path || !stroke)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_path(ctx, path, stroke, &ctm, &rect));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jrect;
}

typedef struct
{
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

	if (!ctx || !path || !obj)
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

	if (!ctx || !stroke)
		return;

	fz_drop_stroke_state(ctx, stroke);
}

JNIEXPORT jlong JNICALL
FUN(Path_newStrokeState)(JNIEnv *env, jobject self, jint startCap, jint dashCap, jint endCap, jint lineJoin, jfloat lineWidth, jfloat miterLimit, jfloat dashPhase, jfloatArray dash)
{
	fz_context *ctx = get_context(env);
	fz_stroke_state *stroke = NULL;
	jsize len = 0;

	if (!ctx || !dash)
		return 0;

	len = (*env)->GetArrayLength(env, dash);

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
		jni_rethrow(env, ctx);
		return 0;
	}

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

	if (!ctx || !stroke || stroke->dash_len == 0)
		return NULL;

	arr = (*env)->NewFloatArray(env, stroke->dash_len);
	if (!arr)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "JNI creation of floatArray failed");
		return NULL;
	}

	(*env)->SetFloatArrayRegion(env, arr, 0, stroke->dash_len, &stroke->dash_list[0]);

	return arr;
}

/* Text interface */

JNIEXPORT void JNICALL
FUN(Text_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);

	if (!ctx || !text)
		return;

	fz_drop_text(ctx, text);
}

JNIEXPORT jlong JNICALL
FUN(Text_clone)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *old_text = from_Text(env, self);
	fz_text *new_text = NULL;

	if (!ctx || !old_text)
		return 0;

	fz_try(ctx)
		new_text = fz_clone_text(ctx, old_text);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(new_text);
}

JNIEXPORT jlong JNICALL
FUN(Text_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_text *text = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		text = fz_new_text(ctx);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

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

	if (!ctx || !text || !stroke)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_text(ctx, text, stroke, &ctm, &rect));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jrect;
}

JNIEXPORT void JNICALL
FUN(Text_showGlyph)(JNIEnv *env, jobject self, jobject jfont, jobject jtrm, jint glyph, jint unicode, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_font *font = from_Font(env, jfont);
	fz_matrix trm = from_Matrix(env, jtrm);

	if (!ctx || !text || !font)
		return;

	fz_try(ctx)
		fz_show_glyph(ctx, text, font, &trm, glyph, unicode, wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Text_showString)(JNIEnv *env, jobject self, jobject jfont, jobject jtrm, jstring jstr, jboolean wmode)
{
	fz_context *ctx = get_context(env);
	fz_text *text = from_Text(env, self);
	fz_font *font = from_Font(env, jfont);
	fz_matrix trm = from_Matrix(env, jtrm);
	const char *str;

	if (!ctx || !text || !font || !jstr)
		return;

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "showString failed");
		return;
	}

	fz_try(ctx)
		fz_show_string(ctx, text, font, &trm, str, wmode, 0, FZ_BIDI_NEUTRAL, FZ_LANG_UNSET);
	fz_always(ctx)
		if (str)
			(*env)->ReleaseStringUTFChars(env, jstr, str);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return;
	}

	(*env)->SetFloatField(env, jtrm, fid_Matrix_e, trm.e);
	(*env)->SetFloatField(env, jtrm, fid_Matrix_f, trm.f);
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

	if (!ctx || !walker || text->head == NULL)
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

	if (!ctx || !image)
		return;

	fz_drop_image(ctx, image);
}

JNIEXPORT jlong JNICALL
FUN(Image_newNativeFromPixmap)(JNIEnv *env, jobject self, jobject jpixmap)
{
	fz_context *ctx = get_context(env);
	fz_pixmap *pixmap = from_Pixmap(env, jpixmap);
	fz_image *image = NULL;

	if (!ctx || !pixmap)
		return 0;

	fz_try(ctx)
		image = fz_new_image_from_pixmap(ctx, pixmap, NULL);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(image);
}

JNIEXPORT jlong JNICALL
FUN(Image_newNativeFromFile)(JNIEnv *env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	const char *filename = NULL;
	fz_image *image = NULL;

	if (!ctx || !jfilename)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (!filename)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Image constructor failed");
		return 0;
	}

	fz_try(ctx)
		image = fz_new_image_from_file(ctx, filename);
	fz_always(ctx)
		if (filename)
			(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

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

JNIEXPORT jobject JNICALL
FUN(Image_getColorSpace)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *image = from_Image(env, self);
	jobject jcs = NULL;

	if (!ctx || !image)
		return NULL;

	fz_try (ctx)
		jcs = to_ColorSpace(ctx, env, image->colorspace);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jcs;
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
	if (!image) return JNI_FALSE;
	return image->imagemask ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(Image_getInterpolate)(JNIEnv *env, jobject self)
{
	fz_image *image = from_Image(env, self);
	if (!image) return JNI_FALSE;
	return image->interpolate ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
FUN(Image_getMask)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *img = from_Image(env, self);
	jobject jmask = NULL;

	if (!ctx || !img || img->mask == NULL)
		return NULL;

	fz_try(ctx)
		jmask = to_Image(ctx, env, img->mask);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jmask;
}

JNIEXPORT jobject JNICALL
FUN(Image_toPixmap)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_image *img = from_Image(env, self);
	fz_pixmap *pixmap = NULL;

	if (!ctx || !img)
		return NULL;

	fz_try(ctx)
		pixmap = fz_get_pixmap_from_image(ctx, img, NULL, NULL, NULL, NULL);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Pixmap_safe_own(ctx, env, pixmap);
}

/* Annotation Interface */

JNIEXPORT void JNICALL
FUN(Annotation_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);

	if (!ctx || !annot)
		return;

	fz_drop_annot(ctx, annot);
}

JNIEXPORT void JNICALL
FUN(Annotation_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);
	fz_device *dev = from_Device(env, jdev);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie= from_Cookie(env, jcookie);
	NativeDeviceInfo *info;

	if (!ctx || !annot || !dev)
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
	fz_annot *annot = from_Annotation(env, self);

	if (!ctx || !annot)
		return 0;

	fz_try(ctx)
		annot = fz_next_annot(ctx, annot);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(annot);
}

JNIEXPORT jobject JNICALL
FUN(Annotation_toPixmap)(JNIEnv *env, jobject self, jobject jctm, jobject jcs, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_pixmap *pixmap = NULL;

	if (!ctx || !cs)
		return NULL;

	fz_try(ctx)
		pixmap = fz_new_pixmap_from_annot(ctx, annot, &ctm, cs, alpha);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Pixmap_safe_own(ctx, env, pixmap);
}

JNIEXPORT jobject JNICALL
FUN(Annotation_getBounds)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);
	jobject jrect = NULL;
	fz_rect rect;

	if (!ctx || !annot)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_annot(ctx, annot, &rect));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jrect;
}

JNIEXPORT jobject JNICALL
FUN(Annotation_toDisplayList)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_annot *annot = from_Annotation(env, self);
	fz_display_list *list = NULL;

	if (!ctx || !annot)
		return NULL;

	fz_try(ctx)
		list = fz_new_display_list_from_annot(ctx, annot);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_DisplayList_safe_own(ctx, env, list);
}

/* Document interface */

JNIEXPORT void JNICALL
FUN(Document_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);

	if (!ctx || !doc)
		return;

	fz_drop_document(ctx, doc);
}

JNIEXPORT jlong JNICALL
FUN(Document_newNativeWithPath)(JNIEnv *env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = NULL;
	const char *filename = NULL;

	if (!ctx || !jfilename)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (!filename)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "Document constructor failed");
		return 0;
	}

	fz_try(ctx)
		doc = fz_open_document(ctx, filename);
	fz_always(ctx)
		if (filename)
			(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(doc);
}

JNIEXPORT jboolean JNICALL
FUN(Document_needsPassword)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	int okay = 0;

	if (!ctx || !doc)
		return JNI_FALSE;

	fz_try(ctx)
		okay = fz_needs_password(ctx, doc);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return okay ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(Document_authenticatePassword)(JNIEnv *env, jobject self, jstring jpassword)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	const char *password = NULL;
	int okay = 0;

	if (!ctx || !doc)
		return JNI_FALSE;

	if (!jpassword)
		password = "";
	else
	{
		password = (*env)->GetStringUTFChars(env, jpassword, NULL);
		if (!password)
		{
			jni_throw(env, FZ_ERROR_GENERIC, "autenticatePassword failed");
			return JNI_FALSE;
		}
	}

	fz_try(ctx)
		okay = fz_authenticate_password(ctx, doc, password);
	fz_always(ctx)
		if (password)
			(*env)->ReleaseStringUTFChars(env, jpassword, password);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return okay ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
FUN(Document_countPages)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	int count = 0;

	if (!ctx || !doc)
		return 0;

	fz_try(ctx)
		count = fz_count_pages(ctx, doc);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return count;
}

JNIEXPORT jboolean JNICALL
FUN(Document_isReflowable)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	int is_reflowable = 0;

	if (!ctx || !doc)
		return JNI_FALSE;

	fz_try(ctx)
		is_reflowable = fz_is_document_reflowable(ctx, doc);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return is_reflowable ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
FUN(Document_layout)(JNIEnv *env, jobject self, jfloat w, jfloat h, jfloat em)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);

	if (!ctx || !doc)
		return;

	fz_try(ctx)
		fz_layout_document(ctx, doc, w, h, em);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jobject JNICALL
FUN(Document_loadPage)(JNIEnv *env, jobject self, jint number)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	fz_page *page = NULL;

	if (!ctx || !doc)
		return NULL;

	fz_try(ctx)
		page = fz_load_page(ctx, doc, number);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Page_safe_own(ctx, env, page);
}

JNIEXPORT jobject JNICALL
FUN(Document_getMetaData)(JNIEnv *env, jobject self, jstring jkey)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	const char *key;
	char info[256];

	if (!ctx || !doc || !jkey)
		return NULL;

	key = (*env)->GetStringUTFChars(env, jkey, NULL);
	if (!key)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "getMetaData failed");
		return NULL;
	}

	fz_try(ctx)
		fz_lookup_metadata(ctx, doc, key, info, sizeof info);
	fz_always(ctx)
		if (key)
			(*env)->ReleaseStringUTFChars(env, jkey, key);
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
	fz_document *doc = from_Document(env, self);
	pdf_document *idoc = pdf_specifics(ctx, doc);
	int cryptVer;

	if (!ctx || !idoc)
		return JNI_FALSE; // Not a PDF

	cryptVer = pdf_crypt_version(ctx, idoc);
	return (cryptVer == 0) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jobject JNICALL
FUN(Document_loadOutline)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	fz_outline *outline = NULL;
	jobject joutline = NULL;

	if (!ctx || !doc)
		return NULL;

	fz_var(outline);

	fz_try(ctx)
		outline = fz_load_outline(ctx, doc);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	if (outline)
	{
		joutline = to_Outline_safe(ctx, env, outline);
		if (!joutline)
			jni_throw(env, FZ_ERROR_GENERIC, "loadOutline failed");
		fz_drop_outline(ctx, outline);
	}

	return joutline;
}

JNIEXPORT jobject JNICALL
FUN(Document_toPDFDocument)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document *doc = from_Document(env, self);
	pdf_document *pdf = NULL;

	if (!ctx || !doc)
		return NULL;

	fz_try(ctx)
		pdf = pdf_specifics(ctx, doc);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFDocument_safe(ctx, env, pdf);
}

/* Page interface */

JNIEXPORT void JNICALL
FUN(Page_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);

	if (!ctx || !page)
		return;

	fz_drop_page(ctx, page);
}

JNIEXPORT jobject JNICALL
FUN(Page_toPixmap)(JNIEnv *env, jobject self, jobject jctm, jobject jcs, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_pixmap *pixmap = NULL;

	if (!ctx || !page || !cs)
		return NULL;

	fz_try(ctx)
		pixmap = fz_new_pixmap_from_page(ctx, page, &ctm, cs, alpha);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Pixmap_safe_own(ctx, env, pixmap);
}

JNIEXPORT jobject JNICALL
FUN(Page_getBounds)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	jobject jrect = NULL;
	fz_rect rect;

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
		jrect = to_Rect(ctx, env, fz_bound_page(ctx, page, &rect));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jrect;
}

JNIEXPORT void JNICALL
FUN(Page_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_device *dev = from_Device(env, jdev);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	NativeDeviceInfo *info;

	if (!ctx || !page || !dev)
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
	fz_page *page = from_Page(env, self);
	fz_device *dev = from_Device(env, jdev);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	NativeDeviceInfo *info;

	if (!ctx || !page || !dev)
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
	fz_annot *annots = NULL;
	jobject jannots = NULL;
	int annot_count;
	int i;

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
	{
		annots = fz_first_annot(ctx, page);

		/* Count the annotations */
		annot = annots;
		for (annot_count = 0; annot; annot_count++)
			annot = fz_next_annot(ctx, annot);

		if (annot_count == 0)
			break; /* No annotations! */

		jannots = (*env)->NewObjectArray(env, annot_count, cls_Annot, NULL);
		if (!jannots)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getAnnotations failed (1)");

		/* Now run through actually creating the annotation objects */
		annot = annots;
		for (i = 0; annot && i < annot_count; i++)
		{
			jobject jannot = to_Annotation(ctx, env, annot);
			(*env)->SetObjectArrayElement(env, jannots, i, jannot);
			(*env)->DeleteLocalRef(env, jannot);
			annot = fz_next_annot(ctx, annot);
		}
		if (annot || i != annot_count)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getAnnotations failed (2)");
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jannots;
}

JNIEXPORT jobject JNICALL
FUN(Page_getLinks)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_link *link = NULL;
	fz_link *links = NULL;
	jobject jlinks = NULL;
	int link_count;
	int i;

	if (!ctx || !page)
		return NULL;

	fz_var(links);

	fz_try(ctx)
	{
		links = fz_load_links(ctx, page);

		/* Count the links */
		link = links;
		for (link_count = 0; link; link_count++)
			link = link->next;

		if (link_count == 0)
			break; /* No links! */

		jlinks = (*env)->NewObjectArray(env, link_count, cls_Link, NULL);
		if (!jlinks)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getLinks failed (1)");

		/* Now run through actually creating the link objects */
		link = links;
		for (i = 0; link && i < link_count; i++)
		{
			jobject jbounds = NULL;
			jobject jlink = NULL;
			jobject juri = NULL;
			int page = 0;

			jbounds = to_Rect(ctx, env, &link->rect);
			if (link->dest.kind == FZ_LINK_GOTO)
				page = link->dest.ld.gotor.page;
			else if (link->dest.kind == FZ_LINK_URI)
				juri = (*env)->NewStringUTF(env, link->dest.ld.uri.uri);

			jlink = (*env)->NewObject(env, cls_Link, mid_Link_init, jbounds, page, juri);
			if (jbounds)
				(*env)->DeleteLocalRef(env, jbounds);
			if (juri)
				(*env)->DeleteLocalRef(env, juri);
			if (!jlink)
				break;

			(*env)->SetObjectArrayElement(env, jlinks, i, jlink);
			(*env)->DeleteLocalRef(env, jlink);
			link = link->next;
		}
		if (link || i != link_count)
			fz_throw(ctx, FZ_ERROR_GENERIC, "getLinks failed (2)");
	}
	fz_always(ctx)
		fz_drop_link(ctx, links);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jlinks;
}

JNIEXPORT jobject JNICALL
FUN(Page_search)(JNIEnv *env, jobject self, jstring jneedle)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_rect hits[256] = { 0 };
	const char *needle = NULL;
	jobject jhits = NULL;
	int n = 0;
	int i;

	if (!ctx || !page || !jneedle)
		return NULL;

	needle = (*env)->GetStringUTFChars(env, jneedle, NULL);
	if (!needle)
		return NULL;

	fz_try(ctx)
		n = fz_search_page(ctx, page, needle, hits, nelem(hits));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jneedle, needle);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jhits = (*env)->NewObjectArray(env, n, cls_Rect, NULL);
	if (!jhits)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "search failed");
		return NULL;
	}

	fz_try(ctx)
	{
		for (i = 0; i < n; i++)
		{
			jobject jhit = to_Rect(ctx, env, &hits[i]);
			(*env)->SetObjectArrayElement(env, jhits, i, jhit);
			(*env)->DeleteLocalRef(env, jhit);
		}
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jhits;
}

JNIEXPORT jobject JNICALL
FUN(Page_toDisplayList)(JNIEnv *env, jobject self, jboolean no_annotations)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_display_list *list = NULL;

	if (!ctx || !page)
		return NULL;

	fz_try(ctx)
		if (no_annotations)
			list = fz_new_display_list_from_page_contents(ctx, page);
		else
			list = fz_new_display_list_from_page(ctx, page);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_DisplayList_safe_own(ctx, env, list);
}

JNIEXPORT jobject JNICALL
FUN(Page_toStructuredText)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);
	fz_stext_sheet *sheet = NULL;
	fz_stext_page *text = NULL;

	if (!ctx || !page)
		return NULL;

	fz_var(sheet);

	fz_try(ctx)
	{
		sheet = fz_new_stext_sheet(ctx);
		text = fz_new_stext_page_from_page(ctx, page, sheet);
	}
	fz_always(ctx)
		fz_drop_stext_sheet(ctx, sheet);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_StructuredText_safe_own(ctx, env, text);
}

JNIEXPORT jbyteArray JNICALL
FUN(Page_textAsHtml)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_page *page = from_Page(env, self);

	fz_stext_sheet *sheet = NULL;
	fz_stext_page *text = NULL;
	fz_device *dev = NULL;
	fz_matrix ctm;
	jbyteArray bArray = NULL;
	fz_buffer *buf = NULL;
	fz_output *out = NULL;

	fz_var(sheet);
	fz_var(text);
	fz_var(dev);
	fz_var(buf);
	fz_var(out);

	fz_try(ctx)
	{
		fz_rect mediabox;

		ctm = fz_identity;
		sheet = fz_new_stext_sheet(ctx);
		text = fz_new_stext_page(ctx, fz_bound_page(ctx, page, &mediabox));
		dev = fz_new_stext_device(ctx, sheet, text);
		fz_run_page(ctx, page, dev, &ctm, NULL);
		fz_close_device(ctx, dev);
		fz_drop_device(ctx, dev);
		dev = NULL;

		fz_analyze_text(ctx, sheet, text);

		buf = fz_new_buffer(ctx, 256);
		out = fz_new_output_with_buffer(ctx, buf);
		fz_printf(ctx, out, "<html>\n");
		fz_printf(ctx, out, "<style>\n");
		fz_printf(ctx, out, "body{margin:0;}\n");
		fz_printf(ctx, out, "div.page{background-color:white;}\n");
		fz_printf(ctx, out, "div.block{margin:0pt;padding:0pt;}\n");
		fz_printf(ctx, out, "div.metaline{display:table;width:100%%}\n");
		fz_printf(ctx, out, "div.line{display:table-row;}\n");
		fz_printf(ctx, out, "div.cell{display:table-cell;padding-left:0.25em;padding-right:0.25em}\n");
		//fz_printf(ctx, out, "p{margin:0;padding:0;}\n");
		fz_printf(ctx, out, "</style>\n");
		fz_printf(ctx, out, "<body style=\"margin:0\"><div style=\"padding:10px\" id=\"content\">");
		fz_print_stext_page_html(ctx, out, text);
		fz_printf(ctx, out, "</div></body>\n");
		fz_printf(ctx, out, "<style>\n");
		fz_print_stext_sheet(ctx, out, sheet);
		fz_printf(ctx, out, "</style>\n</html>\n");
		fz_drop_output(ctx, out);
		out = NULL;

		bArray = (*env)->NewByteArray(env, buf->len);
		if (!bArray)
			fz_throw(ctx, FZ_ERROR_GENERIC, "Failed to make byteArray");
		(*env)->SetByteArrayRegion(env, bArray, 0, buf->len, (jbyte *) buf->data);

	}
	fz_always(ctx)
	{
		fz_drop_stext_page(ctx, text);
		fz_drop_stext_sheet(ctx, sheet);
		fz_drop_device(ctx, dev);
		fz_drop_output(ctx, out);
		fz_drop_buffer(ctx, buf);
	}
	fz_catch(ctx)
	{
		jclass cls = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
		if (cls)
			(*env)->ThrowNew(env, cls, "Out of memory in MuPDFCore_textAsHtml");
		(*env)->DeleteLocalRef(env, cls);

		return NULL;
	}

	return bArray;
}


/* Cookie interface */

JNIEXPORT void JNICALL
FUN(Cookie_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = from_Cookie(env, self);

	if (!ctx || !cookie)
		return;

	fz_free(ctx, cookie);
}

JNIEXPORT jlong JNICALL
FUN(Cookie_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		cookie = fz_malloc_struct(ctx, fz_cookie);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(cookie);
}

JNIEXPORT void JNICALL
FUN(Cookie_abort)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_cookie *cookie = from_Cookie(env, self);

	if (!ctx || !cookie)
		return;

	cookie->abort = 1;
}

/* DisplayList interface */

JNIEXPORT jlong JNICALL
FUN(DisplayList_newNative)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);

	fz_display_list *list = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		list = fz_new_display_list(ctx, NULL);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(list);
}

JNIEXPORT void JNICALL
FUN(DisplayList_run)(JNIEnv *env, jobject self, jobject jdev, jobject jctm, jobject jrect, jobject jcookie)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);
	fz_device *dev = from_Device(env, jdev);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_cookie *cookie = from_Cookie(env, jcookie);
	NativeDeviceInfo *info;
	fz_rect local_rect;
	fz_rect *rect = NULL;

	if (!ctx || !list || !dev)
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

	if (!ctx || !list)
		return;

	fz_drop_display_list(ctx, list);
}

JNIEXPORT jobject JNICALL
FUN(DisplayList_toPixmap)(JNIEnv *env, jobject self, jobject jctm, jobject jcs, jboolean alpha)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);
	fz_matrix ctm = from_Matrix(env, jctm);
	fz_colorspace *cs = from_ColorSpace(env, jcs);
	fz_pixmap *pixmap = NULL;

	if (!ctx || !list || !cs)
		return NULL;

	fz_try(ctx)
		pixmap = fz_new_pixmap_from_display_list(ctx, list, &ctm, cs, alpha);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Pixmap_safe_own(ctx, env, pixmap);
}

JNIEXPORT jobject JNICALL
FUN(DisplayList_toStructuredText)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);
	fz_stext_sheet *sheet = NULL;
	fz_stext_page *text = NULL;

	if (!ctx || !list)
		return NULL;

	fz_var(sheet);

	fz_try(ctx)
	{
		sheet = fz_new_stext_sheet(ctx);
		text = fz_new_stext_page_from_display_list(ctx, list, sheet);
	}
	fz_always(ctx)
		fz_drop_stext_sheet(ctx, sheet);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_StructuredText_safe_own(ctx, env, text);
}

JNIEXPORT jobject JNICALL
FUN(DisplayList_search)(JNIEnv *env, jobject self, jstring jneedle)
{
	fz_context *ctx = get_context(env);
	fz_display_list *list = from_DisplayList(env, self);
	fz_rect hits[256] = { 0 };
	const char *needle = NULL;
	jobject jhits = NULL;
	int n = 0;
	int i;

	if (!ctx || !list || !jneedle)
		return NULL;

	needle = (*env)->GetStringUTFChars(env, jneedle, NULL);
	if (!needle)
		return NULL;

	fz_try(ctx)
		n = fz_search_display_list(ctx, list, needle, hits, nelem(hits));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jneedle, needle);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jhits = (*env)->NewObjectArray(env, n, cls_Rect, NULL);
	if (!jhits)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "search failed");
		return NULL;
	}

	fz_try(ctx)
	{
		for (i = 0; i < n; i++)
		{
			jobject jhit = to_Rect(ctx, env, &hits[i]);
			(*env)->SetObjectArrayElement(env, jhits, i, jhit);
			(*env)->DeleteLocalRef(env, jhit);
		}
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jhits;
}

/* Buffer interface */

JNIEXPORT void JNICALL
FUN(Buffer_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);

	if (!ctx || !buf)
		return;

	fz_drop_buffer(ctx, buf);
}

JNIEXPORT jlong JNICALL
FUN(Buffer_newNativeBuffer)(JNIEnv *env, jobject self, jint n)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = NULL;

	if (!ctx)
		return 0;

	fz_try(ctx)
		buf = fz_new_buffer(ctx, n);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(buf);
}

JNIEXPORT jint JNICALL
FUN(Buffer_getLength)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);

	if (!ctx || !buf)
		return 0;

	return buf->len;
}

JNIEXPORT jint JNICALL
FUN(Buffer_readByte)(JNIEnv *env, jobject self, jint jat)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	size_t at = (size_t) jat;

	if (!ctx || !buf || jat < 0)
		return -1;

	if (at >= buf->len)
		return -1;

	return buf->data[at];
}

JNIEXPORT jint JNICALL
FUN(Buffer_readBytes)(JNIEnv *env, jobject self, jint jat, jobject jbs)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	size_t at = (size_t) jat;
	jbyte *bs = NULL;
	size_t len = 0;
	size_t remaining_input = 0;
	size_t remaining_output = 0;

	if (!ctx || !buf || jat < 0 || !jbs)
		return -1;

	if (at >= buf->len)
		return -1;

	remaining_input = buf->len - at;
	remaining_output = (*env)->GetArrayLength(env, jbs);
	len = fz_mini(0, remaining_output);
	len = fz_mini(len, remaining_input);

	bs = (*env)->GetByteArrayElements(env, jbs, NULL);
	memcpy(bs, &buf->data[at], len);
	(*env)->ReleaseByteArrayElements(env, jbs, bs, JNI_ABORT);

	return len;
}

JNIEXPORT jint JNICALL
FUN(Buffer_readBytesInto)(JNIEnv *env, jobject self, jint jat, jobject jbs, jint joff, jint jlen)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	size_t at = (size_t) jat;
	jbyte *bs = NULL;
	jsize off = (jsize) joff;
	jsize len = (jsize) jlen;
	jsize bslen = 0;

	if (!ctx || !buf || jat < 0)
		return -1;

	if (!jbs)
		(*env)->ThrowNew(env, cls_NullPointerException, "buffer is null");

	bslen = (*env)->GetArrayLength(env, jbs);
	if (joff < 0)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "offset is negative");
	if (jlen < 0)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "length is negative");
	if (len > bslen - off)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "offset + length is outside of buffer");

	if (at >= buf->len)
		return -1;

	len = fz_mini(len, buf->len - at);

	bs = (*env)->GetByteArrayElements(env, jbs, NULL);
	memcpy(&bs[off], &buf->data[at], len);
	(*env)->ReleaseByteArrayElements(env, jbs, bs, JNI_ABORT);

	return len;
}

JNIEXPORT void JNICALL
FUN(Buffer_writeByte)(JNIEnv *env, jobject self, jbyte b)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);

	if (!ctx || !buf)
		return;

	fz_try(ctx)
		fz_write_buffer_byte(ctx, buf, b);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Buffer_writeBytes)(JNIEnv *env, jobject self, jobject jbs)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	jsize len = 0;
	jbyte *bs = NULL;

	if (!ctx || !buf || !jbs)
		return;

	len = (*env)->GetArrayLength(env, jbs);
	bs = (*env)->GetByteArrayElements(env, jbs, NULL);

	fz_try(ctx)
		fz_write_buffer(ctx, buf, bs, len);
	fz_always(ctx)
		(*env)->ReleaseByteArrayElements(env, jbs, bs, JNI_ABORT);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Buffer_writeBytesFrom)(JNIEnv *env, jobject self, jobject jbs, jint joff, jint jlen)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	jbyte *bs = NULL;
	jsize off = (jsize) joff;
	jsize len = (jsize) jlen;
	jsize bslen = 0;

	if (!ctx || !buf)
		return;

	if (!jbs)
		(*env)->ThrowNew(env, cls_NullPointerException, "buffer is null");

	bslen = (*env)->GetArrayLength(env, jbs);
	if (joff < 0)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "offset is negative");
	if (jlen < 0)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "length is negative");
	if (off + len >= bslen)
		(*env)->ThrowNew(env, cls_IndexOutOfBoundsException, "offset + length is outside of buffer");

	bs = (*env)->GetByteArrayElements(env, jbs, NULL);

	fz_try(ctx)
		fz_write_buffer(ctx, buf, &bs[off], len);
	fz_always(ctx)
		(*env)->ReleaseByteArrayElements(env, jbs, bs, JNI_ABORT);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}


JNIEXPORT void JNICALL
FUN(Buffer_writeBuffer)(JNIEnv *env, jobject self, jobject jbuf)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	fz_buffer *cat = from_Buffer(env, jbuf);

	if (!ctx || !buf || !cat)
		return;

	fz_try(ctx)
		fz_append_buffer(ctx, buf, cat);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Buffer_writeRune)(JNIEnv *env, jobject self, jint rune)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);

	if (!ctx || !buf)
		return;

	fz_try(ctx)
		fz_write_buffer_rune(ctx, buf, rune);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Buffer_writeLine)(JNIEnv *env, jobject self, jstring jline)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	const char *line = NULL;

	if (!ctx || !buf || !jline)
		return;

	line = (*env)->GetStringUTFChars(env, jline, NULL);
	if (!line)
		return;

	fz_try(ctx)
	{
		fz_write_buffer(ctx, buf, line, strlen(line));
		fz_write_buffer_byte(ctx, buf, '\n');
	}
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jline, line);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(Buffer_writeLines)(JNIEnv *env, jobject self, jobject jlines)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	int i = 0;
	jsize len = 0;

	if (!ctx || !buf || !jlines)
		return;

	len = (*env)->GetArrayLength(env, jlines);

	for (i = 0; i < len; ++i)
	{
		jobject jline = (*env)->GetObjectArrayElement(env, jlines, i);
		const char *line = NULL;

		if (!jline)
			continue;

		line = (*env)->GetStringUTFChars(env, jline, NULL);
		if (!line)
		{
			jni_throw(env, FZ_ERROR_GENERIC, "writeLines failed");
			return;
		}

		fz_try(ctx)
		{
			fz_write_buffer(ctx, buf, line, strlen(line));
			fz_write_buffer_byte(ctx, buf, '\n');
		}
		fz_always(ctx)
			(*env)->ReleaseStringUTFChars(env, jline, line);
		fz_catch(ctx)
		{
			jni_rethrow(env, ctx);
			return;
		}
	}
}

JNIEXPORT void JNICALL
FUN(Buffer_save)(JNIEnv *env, jobject self, jstring jfilename)
{
	fz_context *ctx = get_context(env);
	fz_buffer *buf = from_Buffer(env, self);
	const char *filename = NULL;

	if (!ctx || !buf || !jfilename)
		return;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (!filename)
		return;

	fz_try(ctx)
		fz_save_buffer(ctx, buf, filename);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

/* DocumentWriter interface */

JNIEXPORT void JNICALL
FUN(DocumentWriter_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document_writer *wri = from_DocumentWriter(env, self);

	if (!ctx || !wri)
		return;

	fz_drop_document_writer(ctx, wri);
}

JNIEXPORT jlong JNICALL
FUN(DocumentWriter_newNativeDocumentWriter)(JNIEnv *env, jobject self, jstring jfilename, jstring jformat, jstring joptions)
{
	fz_context *ctx = get_context(env);
	fz_document_writer *wri = from_DocumentWriter(env, self);
	const char *filename = NULL;
	const char *format = NULL;
	const char *options = NULL;

	if (!ctx || !wri || !jfilename)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (!filename)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "DocumentWriter constructor failed (1)");
		return 0;
	}
	if (jformat)
	{
		format = (*env)->GetStringUTFChars(env, jformat, NULL);
		if (!format)
		{
			(*env)->ReleaseStringUTFChars(env, jfilename, filename);
			jni_throw(env, FZ_ERROR_GENERIC, "DocumentWriter constructor failed (2)");
			return 0;
		}
	}
	if (joptions)
	{
		options = (*env)->GetStringUTFChars(env, joptions, NULL);
		if (!options)
		{
			if (format)
				(*env)->ReleaseStringUTFChars(env, jformat, format);
			(*env)->ReleaseStringUTFChars(env, jfilename, filename);
			jni_throw(env, FZ_ERROR_GENERIC, "DocumentWriter constructor failed (3)");
			return 0;
		}
	}

	fz_try(ctx)
		wri = fz_new_document_writer(ctx, filename, format, options);
	fz_always(ctx)
	{
		if (options)
			(*env)->ReleaseStringUTFChars(env, joptions, options);
		if (format)
			(*env)->ReleaseStringUTFChars(env, jformat, format);
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return jlong_cast(wri);
}

JNIEXPORT jobject JNICALL
FUN(DocumentWriter_beginPage)(JNIEnv *env, jobject self, jobject jmediabox)
{
	fz_context *ctx = get_context(env);
	fz_document_writer *wri = from_DocumentWriter(env, self);
	fz_rect mediabox = from_Rect(env, jmediabox);
	fz_device *device = NULL;

	if (!ctx || !wri)
		return NULL;

	fz_try(ctx)
		device = fz_begin_page(ctx, wri, &mediabox);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_Device_safe_own(ctx, env, device);
}

JNIEXPORT void JNICALL
FUN(DocumentWriter_endPage)(JNIEnv *env, jobject self, jobject jdev)
{
	fz_context *ctx = get_context(env);
	fz_document_writer *wri = from_DocumentWriter(env, self);
	fz_device *device = from_Device(env, jdev);

	if (!ctx || !wri || !device)
		return;

	fz_try(ctx)
		fz_end_page(ctx, wri, device);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(DocumentWriter_close)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_document_writer *wri = from_DocumentWriter(env, self);

	if (!ctx || !wri)
		return;

	fz_try(ctx)
		fz_close_document_writer(ctx, wri);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

/* StructuredText interface */

JNIEXPORT void JNICALL
FUN(StructuredText_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stext_page *text = from_StructuredText(env, self);

	if (!ctx || !text)
		return;

	fz_drop_stext_page(ctx, text);
}

JNIEXPORT jobject JNICALL
FUN(StructuredText_search)(JNIEnv *env, jobject self, jstring jneedle)
{
	fz_context *ctx = get_context(env);
	fz_stext_page *text = from_StructuredText(env, self);
	fz_rect hits[256] = { 0 };
	const char *needle = NULL;
	jobject jhits = NULL;
	int n = 0;
	int i;

	if (!ctx || !text || !jneedle)
		return NULL;

	needle = (*env)->GetStringUTFChars(env, jneedle, NULL);
	if (!needle)
		return NULL;

	fz_try(ctx)
		n = fz_search_stext_page(ctx, text, needle, hits, nelem(hits));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jneedle, needle);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jhits = (*env)->NewObjectArray(env, n, cls_Rect, NULL);
	if (!jhits)
		fz_throw(ctx, FZ_ERROR_GENERIC, "search failed");

	fz_try(ctx)
	{
		for (i = 0; i < n; i++)
		{
			jobject jhit = to_Rect(ctx, env, &hits[i]);
			(*env)->SetObjectArrayElement(env, jhits, i, jhit);
			(*env)->DeleteLocalRef(env, jhit);
		}
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jhits;
}

JNIEXPORT jobject JNICALL
FUN(StructuredText_highlight)(JNIEnv *env, jobject self, jobject jrect)
{
	fz_context *ctx = get_context(env);
	fz_stext_page *text = from_StructuredText(env, self);
	fz_rect rect = from_Rect(env, jrect);
	fz_rect hits[256] = { 0 };
	jobject jhits = NULL;
	int n = 0;
	int i;

	if (!ctx || !text)
		return NULL;

	fz_try(ctx)
		n = fz_highlight_selection(ctx, text, rect, hits, nelem(hits));
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jhits = (*env)->NewObjectArray(env, n, cls_Rect, NULL);
	if (!jhits)
		fz_throw(ctx, FZ_ERROR_GENERIC, "search failed (1)");

	fz_try(ctx)
	{
		for (i = 0; i < n; i++)
		{
			jobject jhit = to_Rect(ctx, env, &hits[i]);
			(*env)->SetObjectArrayElement(env, jhits, i, jhit);
			(*env)->DeleteLocalRef(env, jhit);
		}
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jhits;
}

JNIEXPORT jobject JNICALL
FUN(StructuredText_copy)(JNIEnv *env, jobject self, jobject jrect)
{
	fz_context *ctx = get_context(env);
	fz_stext_page *text = from_StructuredText(env, self);
	fz_rect rect = from_Rect(env, jrect);
	jobject jstring = NULL;
	char *s = NULL;

	if (!ctx || !text)
		return NULL;

	fz_var(s);

	fz_try(ctx)
		s = fz_copy_selection(ctx, text, rect);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jstring = (*env)->NewStringUTF(env, s);
	fz_free(ctx, s);

	return jstring;
}

JNIEXPORT jobject JNICALL
FUN(StructuredText_getBlocks)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_stext_page *text = from_StructuredText(env, self);

	jobject barr = NULL;
	jobject larr = NULL;
	jobject sarr = NULL;
	jobject carr = NULL;
	jobject jrect = NULL;

	int b;
	int l;
	int s;
	int c;

	fz_stext_block *block = NULL;
	fz_stext_line *line = NULL;
	fz_stext_span *span = NULL;

	jobject jblock = NULL;
	jobject jline = NULL;
	jobject jspan = NULL;
	jobject jchar = NULL;

	fz_rect sbbox;
	fz_rect bbox;
	fz_stext_char *ch = NULL;

	//  create block array
	barr = (*env)->NewObjectArray(env, text->len, cls_TextBlock, NULL);
	if (!barr)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (1)");
		return NULL;
	}

	for (b = 0; b < text->len; b++)
	{
		//  only do text blocks
		if (text->blocks[b].type != FZ_PAGE_BLOCK_TEXT)
			continue;

		//  make a block
		block = text->blocks[b].u.text;
		jblock = (*env)->NewObject(env, cls_TextBlock, mid_TextBlock_init, self);
		if (!jblock)
		{
			jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (2)");
			return NULL;
		}

		//  set block's bbox
		jrect = to_Rect(ctx, env, &(block->bbox));
		(*env)->SetObjectField(env, jblock, fid_TextBlock_bbox, jrect);
		(*env)->DeleteLocalRef(env, jrect);

		//  create block's line array
		larr = (*env)->NewObjectArray(env, block->len, cls_TextLine, NULL);
		if (!larr)
		{
			jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (3)");
			return NULL;
		}

		for (l = 0; l < block->len; l++)
		{
			//  make a line
			line = &block->lines[l];
			jline = (*env)->NewObject(env, cls_TextLine, mid_TextLine_init, self);
			if (!jline)
			{
				jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (4)");
				return NULL;
			}

			//  set line's bbox
			jrect = to_Rect(ctx, env, &(line->bbox));
			(*env)->SetObjectField(env, jline, fid_TextLine_bbox, jrect);
			(*env)->DeleteLocalRef(env, jrect);

			//  count the spans
			int len = 0;
			for (span = line->first_span; span; span = span->next)
				len++;

			//  create a span array
			sarr = (*env)->NewObjectArray(env, len, cls_TextSpan, NULL);
			if (!sarr)
			{
				jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (5)");
				return NULL;
			}

			for (s=0, span = line->first_span; span; s++, span = span->next)
			{
				//  create a span
				jspan = (*env)->NewObject(env, cls_TextSpan, mid_TextSpan_init, self);
				if (!jspan)
				{
					jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (6)");
					return NULL;
				}

				//  make a char array
				carr = (*env)->NewObjectArray(env, span->len, cls_TextChar, NULL);
				if (!carr)
				{
					jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (7)");
					return NULL;
				}

				sbbox = fz_empty_rect;
				for (c = 0; c < span->len; c++)
				{
					ch = &span->text[c];

					//  create a char
					jchar = (*env)->NewObject(env, cls_TextChar, mid_TextChar_init, self);
					if (!jchar)
					{
						jni_throw(env, FZ_ERROR_GENERIC, "StructuredText_getBlocks failed (8)");
						return NULL;
					}

					//  set the char's bbox
					fz_stext_char_bbox(ctx, &bbox, span, c);
					jrect = to_Rect(ctx, env, &(bbox));
					(*env)->SetObjectField(env, jchar, fid_TextChar_bbox, jrect);
					(*env)->DeleteLocalRef(env, jrect);

					//  set the char's value
					(*env)->SetIntField(env, jchar, fid_TextChar_c, ch->c);

					//  add it to the char array
					(*env)->SetObjectArrayElement(env, carr, c, jchar);
					(*env)->DeleteLocalRef(env, jchar);

					//  add this char's bbox to the containing span's bbox
					fz_union_rect(&sbbox, &bbox);

				}

				//  set the span's bbox
				jrect = to_Rect(ctx, env, &sbbox);
				(*env)->SetObjectField(env, jspan, fid_TextSpan_bbox, jrect);
				(*env)->DeleteLocalRef(env, jrect);

				//  set the span's char array
				(*env)->SetObjectField(env, jspan, fid_TextSpan_chars, carr);
				(*env)->DeleteLocalRef(env, carr);

				//  add it to the span array
				(*env)->SetObjectArrayElement(env, sarr, s, jspan);
				(*env)->DeleteLocalRef(env, jspan);
			}

			//  set the line's span array
			(*env)->SetObjectField(env, jline, fid_TextLine_spans, sarr);
			(*env)->DeleteLocalRef(env, sarr);

			//  add to the line array
			(*env)->SetObjectArrayElement(env, larr, l, jline);
			(*env)->DeleteLocalRef(env, jline);
		}

		//  set the block's line array
		(*env)->SetObjectField(env, jblock, fid_TextBlock_lines, larr);
		(*env)->DeleteLocalRef(env, larr);

		//  add to the block array
		(*env)->SetObjectArrayElement(env, barr, b, jblock);
		(*env)->DeleteLocalRef(env, jblock);
	}

	return barr;
}


/* PDFDocument interface */

JNIEXPORT void JNICALL
FUN(PDFDocument_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);

	if (!ctx || !pdf)
		return;

	fz_drop_document(ctx, (fz_document *) pdf);
}

JNIEXPORT jint JNICALL
FUN(PDFDocument_countObjects)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	int count = 0;

	if (!ctx || !pdf)
		return 0;

	fz_try(ctx)
		count = pdf_xref_len(ctx, pdf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return count;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newNull)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_null(ctx, pdf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newBoolean)(JNIEnv *env, jobject self, jboolean b)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_bool(ctx, pdf, b);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newInteger)(JNIEnv *env, jobject self, jint i)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_int(ctx, pdf, i);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newReal)(JNIEnv *env, jobject self, jfloat f)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_real(ctx, pdf, f);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newString)(JNIEnv *env, jobject self, jstring jstring)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;
	const char *s = NULL;

	if (!ctx || !pdf || !jstring)
		return NULL;

	s = (*env)->GetStringUTFChars(env, jstring, NULL);
	if (!s)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_string(ctx, pdf, s, strlen(s));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jstring, s);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newName)(JNIEnv *env, jobject self, jstring jname)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;
	const char *name = NULL;

	if (!ctx || !pdf || !jname)
		return NULL;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_name(ctx, pdf, name);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newIndirect)(JNIEnv *env, jobject self, jint num, jint gen)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_indirect(ctx, pdf, num, gen);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newArray)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_array(ctx, pdf, 0);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newDictionary)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	jobject jobj = NULL;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_new_dict(ctx, pdf, 0);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(obj), self);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_toDocument)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);

	if (!ctx || !pdf)
		return NULL;

	return to_Document_safe(ctx, env, (fz_document *) pdf);
}

JNIEXPORT jint JNICALL
FUN(PDFDocument_countPages)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	int count = 0;

	if (!ctx || !pdf)
		return 0;

	fz_try(ctx)
		count = pdf_count_pages(ctx, pdf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return count;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_findPage)(JNIEnv *env, jobject self, jint jat)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	size_t at = (size_t) jat;
	pdf_obj *obj = NULL;

	if (!ctx || !pdf || jat < 0)
		return NULL;

	fz_try(ctx)
		obj = pdf_lookup_page_obj(ctx, pdf, at);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe(ctx, env, self, obj);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_getTrailer)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	pdf_obj *obj = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		obj = pdf_trailer(ctx, pdf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe(ctx, env, self, obj);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addObject)(JNIEnv *env, jobject self, jobject jobj)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	pdf_obj *obj = from_PDFObject(env, jobj);

	if (!ctx || !pdf || !obj)
		return NULL;

	fz_try(ctx)
		obj = pdf_add_object_drop(ctx, pdf, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_createObject)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		ind = pdf_new_indirect(ctx, pdf, pdf_create_object(ctx, pdf), 0);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT void JNICALL
FUN(PDFDocument_deleteObject)(JNIEnv *env, jobject self, jint num)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);

	if (!ctx || !pdf)
		return;

	fz_try(ctx)
		pdf_delete_object(ctx, pdf, num);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_newPDFGraftMap)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	pdf_graft_map *map = NULL;

	if (!ctx || !pdf)
		return NULL;

	fz_try(ctx)
		map = pdf_new_graft_map(ctx, pdf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFGraftMap_safe_own(ctx, env, self, map);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_graftObject)(JNIEnv *env, jobject self, jobject jsrc, jobject jobj, jobject jmap)
{
	fz_context *ctx = get_context(env);
	pdf_document *dst = from_PDFDocument(env, self);
	pdf_document *src = from_PDFDocument(env, jsrc);
	pdf_obj *obj = from_PDFObject(env, jobj);
	pdf_graft_map *map = from_PDFGraftMap(env, jmap);

	if (!ctx || !dst || !src || !obj || !map)
		return NULL;

	fz_try(ctx)
		obj = pdf_graft_object(ctx, dst, src, obj, map);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, obj);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addStreamBuffer)(JNIEnv *env, jobject self, jobject jbuf)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_buffer *buf = from_Buffer(env, jbuf);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !buf)
		return NULL;

	fz_try(ctx)
		ind = pdf_add_stream(ctx, pdf, buf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addStreamString)(JNIEnv *env, jobject self, jstring jbuf)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_buffer *buf = NULL;
	const char *sbuf = NULL;
	unsigned char *data = NULL;
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !jbuf)
		return NULL;

	sbuf = (*env)->GetStringUTFChars(env, jbuf, NULL);
	if (!sbuf)
		return NULL;

	fz_var(data);
	fz_var(buf);

	fz_try(ctx)
	{
		int len = strlen(sbuf);
		data = fz_malloc(ctx, len);
		memcpy(data, sbuf, len);
		buf = fz_new_buffer_from_data(ctx, data, len);
		data = NULL;
		ind = pdf_add_stream(ctx, pdf, buf);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
		fz_free(ctx, data);
		(*env)->ReleaseStringUTFChars(env, jbuf, sbuf);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}


JNIEXPORT jobject JNICALL
FUN(PDFDocument_addPageBuffer)(JNIEnv *env, jobject self, jobject jmediabox, jint rotate, jobject jresources, jobject jcontents)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_rect mediabox = from_Rect(env, jmediabox);
	pdf_obj *resources = from_PDFObject(env, jresources);
	fz_buffer *contents = from_Buffer(env, jcontents);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !resources || !contents)
		return NULL;

	fz_try(ctx)
		ind = pdf_add_page(ctx, pdf, &mediabox, rotate, resources, contents);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addPageString)(JNIEnv *env, jobject self, jobject jmediabox, jint rotate, jobject jresources, jstring jcontents)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_rect mediabox = from_Rect(env, jmediabox);
	pdf_obj *resources = from_PDFObject(env, jresources);
	const char *scontents = NULL;
	fz_buffer *contents = NULL;
	unsigned char *data = NULL;
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !resources || !jcontents)
		return NULL;

	scontents = (*env)->GetStringUTFChars(env, jcontents, NULL);
	if (!scontents)
		return NULL;

	fz_var(data);
	fz_var(contents);

	fz_try(ctx)
	{
		int len = strlen(scontents);
		data = fz_malloc(ctx, len);
		contents = fz_new_buffer_from_data(ctx, data, len);
		data = NULL;
		ind = pdf_add_page(ctx, pdf, &mediabox, rotate, resources, contents);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, contents);
		fz_free(ctx, data);
		(*env)->ReleaseStringUTFChars(env, jcontents, scontents);
	}
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT void JNICALL
FUN(PDFDocument_insertPage)(JNIEnv *env, jobject self, jint jat, jobject jpage)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	size_t at = (size_t) jat;
	pdf_obj *page = from_PDFObject(env, jpage);

	if (!ctx || !pdf || jat < 0 || !page)
		return;

	fz_try(ctx)
		pdf_insert_page(ctx, pdf, at, page);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFDocument_deletePage)(JNIEnv *env, jobject self, jint jat)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	size_t at = (size_t) jat;

	if (!ctx || !pdf || jat < 0)
		return;

	fz_try(ctx)
		pdf_delete_page(ctx, pdf, at);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addImage)(JNIEnv *env, jobject self, jobject jimage)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_image *image = from_Image(env, jimage);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !image)
		return NULL;

	fz_try(ctx)
		ind = pdf_add_image(ctx, pdf, image, 0);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addFont)(JNIEnv *env, jobject self, jobject jfont)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_font *font = from_Font(env, jfont);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !font)
		return NULL;

	fz_try(ctx)
		ind = pdf_add_cid_font(ctx, pdf, font);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT jobject JNICALL
FUN(PDFDocument_addSimpleFont)(JNIEnv *env, jobject self, jobject jfont)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	fz_font *font = from_Font(env, jfont);
	pdf_obj *ind = NULL;

	if (!ctx || !pdf || !font)
		return NULL;

	fz_try(ctx)
		ind = pdf_add_simple_font(ctx, pdf, font);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe_own(ctx, env, self, ind);
}

JNIEXPORT jboolean JNICALL
FUN(PDFDocument_hasUnsavedChanges)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	return pdf_has_unsaved_changes(ctx, pdf) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFDocument_canBeSavedIncrementally)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	return pdf_can_be_saved_incrementally(ctx, pdf) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
FUN(PDFDocument_save)(JNIEnv *env, jobject self, jstring jfilename, jstring joptions)
{
	fz_context *ctx = get_context(env);
	pdf_document *pdf = from_PDFDocument(env, self);
	const char *filename = NULL;
	const char *options = NULL;
	pdf_write_options pwo = { 0 };
	int errors = 0;

	if (!ctx || !pdf || !jfilename)
		return 0;

	filename = (*env)->GetStringUTFChars(env, jfilename, NULL);
	if (!filename)
		return 0;

	if (joptions)
	{
		options = (*env)->GetStringUTFChars(env, joptions, NULL);
		if (!options)
			return 0;
	}

	fz_try(ctx)
	{
		pdf_parse_write_options(ctx, &pwo, options);
		pwo.errors = &errors;
		pdf_save_document(ctx, pdf, filename, &pwo);
	}
	fz_always(ctx)
	{
		if (options)
			(*env)->ReleaseStringUTFChars(env, joptions, options);
		(*env)->ReleaseStringUTFChars(env, jfilename, filename);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);

	return errors;
}

/* PDFObject interface */

JNIEXPORT void JNICALL
FUN(PDFObject_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);

	if (!ctx || !obj)
		return;

	pdf_drop_obj(ctx, obj);
}

JNIEXPORT jint JNICALL
FUN(PDFObject_toIndirect)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int num = 0;

	if (!ctx || !obj)
		return 0;

	fz_try(ctx)
		num = pdf_to_num(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return num;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isIndirect)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_indirect(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isNull)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_null(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isBoolean)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_bool(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isInteger)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_int(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isReal)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_real(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isNumber)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_number(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isString)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_string(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isName)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_name(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isArray)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_array(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isDictionary)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_dict(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_isStream)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_is_stream(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jbyteArray JNICALL
FUN(PDFObject_readStream)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	fz_buffer *buf = NULL;
	jbyteArray arr = NULL;

	if (!ctx || !obj)
		return NULL;

	fz_var(buf);

	fz_try(ctx)
	{
		buf = pdf_load_stream(ctx, obj);

		arr = (*env)->NewByteArray(env, buf->len);
		if (!arr)
			fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of byteArray failed");

		(*env)->SetByteArrayRegion(env, arr, 0, buf->len, (signed char *) &buf->data[0]);
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return arr;
}

JNIEXPORT jbyteArray JNICALL
FUN(PDFObject_readRawStream)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	fz_buffer *buf = NULL;
	jbyteArray arr = NULL;

	if (!ctx || !obj)
		return NULL;

	fz_var(buf);

	fz_try(ctx)
	{
		buf = pdf_load_raw_stream(ctx, obj);

		arr = (*env)->NewByteArray(env, buf->len);
		if (!arr)
			fz_throw(ctx, FZ_ERROR_GENERIC, "JNI creation of byteArray failed");

		(*env)->SetByteArrayRegion(env, arr, 0, buf->len, (signed char *) &buf->data[0]);
	}
	fz_always(ctx)
		fz_drop_buffer(ctx, buf);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return arr;
}

JNIEXPORT void JNICALL
FUN(PDFObject_writeObject)(JNIEnv *env, jobject self, jobject jobj)
{
	fz_context *ctx = get_context(env);
	pdf_obj *ref = from_PDFObject(env, self);
	pdf_document *pdf = pdf_get_bound_document(ctx, ref);
	pdf_obj *obj = from_PDFObject(env, jobj);

	if (!ctx || !pdf || !obj)
		return;

	fz_try(ctx)
		pdf_update_object(ctx, pdf, pdf_to_num(ctx, ref), obj);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_writeStreamBuffer)(JNIEnv *env, jobject self, jobject jbuf)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_document *pdf = pdf_get_bound_document(ctx, obj);
	fz_buffer *buf = from_Buffer(env, jbuf);

	if (!ctx || !pdf || !buf)
		return;

	fz_try(ctx)
		pdf_update_stream(ctx, pdf, obj, buf, 0);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_writeStreamString)(JNIEnv *env, jobject self, jstring jstr)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_document *pdf = pdf_get_bound_document(ctx, obj);
	const char *str = NULL;
	unsigned char *data = NULL;
	fz_buffer *buf = NULL;

	if (!ctx || !pdf || !jstr)
		return;

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "writeStream failed");
		return;
	}

	fz_var(data);
	fz_var(buf);

	fz_try(ctx)
	{
		int len = strlen(str);
		data = fz_malloc(ctx, len);
		memcpy(data, str, len);
		buf = fz_new_buffer_from_data(ctx, data, len);
		data = NULL;
		pdf_update_stream(ctx, pdf, obj, buf, 0);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
		fz_free(ctx, data);
		(*env)->ReleaseStringUTFChars(env, jstr, str);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_writeRawStreamBuffer)(JNIEnv *env, jobject self, jobject jbuf)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_document *pdf = pdf_get_bound_document(ctx, obj);
	fz_buffer *buf = from_Buffer(env, jbuf);

	if (!ctx || !pdf || !buf)
		return;

	fz_try(ctx)
		pdf_update_stream(ctx, pdf, obj, buf, 1);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_writeRawStreamString)(JNIEnv *env, jobject self, jstring jstr)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_document *pdf = pdf_get_bound_document(ctx, obj);
	const char *str = NULL;
	unsigned char *data = NULL;
	fz_buffer *buf = NULL;

	if (!ctx || !pdf || !jstr)
		return;

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "writeStream failed");
		return;
	}

	fz_var(data);
	fz_var(buf);

	fz_try(ctx)
	{
		int len = strlen(str);
		data = fz_malloc(ctx, len);
		memcpy(data, str, len);
		buf = fz_new_buffer_from_data(ctx, data, len);
		data = NULL;
		pdf_update_stream(ctx, pdf, obj, buf, 1);
	}
	fz_always(ctx)
	{
		fz_drop_buffer(ctx, buf);
		fz_free(ctx, data);
		(*env)->ReleaseStringUTFChars(env, jstr, str);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}


JNIEXPORT jobject JNICALL
FUN(PDFObject_resolve)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_obj *ind = NULL;
	jobject jobj = NULL;

	if (!ctx || !obj)
		return NULL;

	fz_try(ctx)
		ind = pdf_resolve_indirect(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jobj = (*env)->NewObject(env, cls_PDFObject, mid_PDFObject_init, jlong_cast(ind), self);
	if (jobj)
		pdf_keep_obj(ctx, ind);

	return jobj;
}

JNIEXPORT jobject JNICALL
FUN(PDFObject_getArray)(JNIEnv *env, jobject self, jint index)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	pdf_obj *val = NULL;

	if (!ctx || !obj)
		return NULL;

	fz_try(ctx)
		val = pdf_array_get(ctx, obj, index);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe(ctx, env, self, val);
}

JNIEXPORT jobject JNICALL
FUN(PDFObject_getDictionary)(JNIEnv *env, jobject self, jstring jname)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	const char *name = NULL;
	pdf_obj *val = NULL;

	if (!ctx || !obj || !jname)
		return NULL;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
		return NULL;

	fz_try(ctx)
		val = pdf_dict_gets(ctx, obj, name);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return to_PDFObject_safe(ctx, env, self, val);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putArrayBoolean)(JNIEnv *env, jobject self, jint index, jboolean b)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);
	pdf_document *pdf = arr ? pdf_get_bound_document(ctx, arr) : NULL;

	if (!ctx || !arr || !pdf)
		return;

	fz_try(ctx)
		if (index == pdf_array_len(ctx, arr))
			pdf_array_push(ctx, arr, pdf_new_bool(ctx, pdf, b));
		else
			pdf_array_put(ctx, arr, index, pdf_new_bool(ctx, pdf, b));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putArrayInteger)(JNIEnv *env, jobject self, jint index, jint i)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);
	pdf_document *pdf = arr ? pdf_get_bound_document(ctx, arr) : NULL;

	if (!ctx || !arr || !pdf)
		return;

	fz_try(ctx)
		if (index == pdf_array_len(ctx, arr))
			pdf_array_push(ctx, arr, pdf_new_int(ctx, pdf, i));
		else
			pdf_array_put(ctx, arr, index, pdf_new_int(ctx, pdf, i));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putArrayFloat)(JNIEnv *env, jobject self, jint index, jfloat f)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);
	pdf_document *pdf = arr ? pdf_get_bound_document(ctx, arr) : NULL;

	if (!ctx || !arr || !pdf)
		return;

	fz_try(ctx)
		if (index == pdf_array_len(ctx, arr))
			pdf_array_push(ctx, arr, pdf_new_real(ctx, pdf, f));
		else
			pdf_array_put(ctx, arr, index, pdf_new_real(ctx, pdf, f));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putArrayString)(JNIEnv *env, jobject self, jint index, jstring jstr)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);
	pdf_document *pdf = arr ? pdf_get_bound_document(ctx, arr) : NULL;
	const char *str = NULL;

	if (!ctx || !arr || !pdf || !jstr)
		return;

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		if (index == pdf_array_len(ctx, arr))
			pdf_array_push(ctx, arr, pdf_new_string(ctx, pdf, str, strlen(str)));
		else
			pdf_array_put(ctx, arr, index, pdf_new_string(ctx, pdf, str, strlen(str)));
	fz_always(ctx)
		if (str)
			(*env)->ReleaseStringUTFChars(env, jstr, str);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putArrayPDFObject)(JNIEnv *env, jobject self, jint index, jobject jobj)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);
	pdf_obj *obj = from_PDFObject(env, jobj);

	if (!ctx || !arr || !obj)
		return;

	fz_try(ctx)
		if (index == pdf_array_len(ctx, arr))
			pdf_array_push(ctx, arr, obj);
		else
			pdf_array_put(ctx, arr, index, obj);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryStringBoolean)(JNIEnv *env, jobject self, jstring jname, jboolean b)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	const char *name = NULL;

	if (!ctx || !dict || !pdf || !jname)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, pdf_new_name(ctx, pdf, name), pdf_new_bool(ctx, pdf, b));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryStringInteger)(JNIEnv *env, jobject self, jstring jname, jint i)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	const char *name = NULL;

	if (!ctx || !dict || !pdf || !jname)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, pdf_new_name(ctx, pdf, name), pdf_new_int(ctx, pdf, i));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryStringFloat)(JNIEnv *env, jobject self, jstring jname, jfloat f)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	const char *name = NULL;

	if (!ctx || !dict || !pdf || !jname)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, pdf_new_name(ctx, pdf, name), pdf_new_real(ctx, pdf, f));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryStringString)(JNIEnv *env, jobject self, jstring jname, jstring jstr)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	const char *name = NULL;
	const char *str = NULL;

	if (!ctx || !dict || !pdf || !jname || !jstr)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		(*env)->ReleaseStringUTFChars(env, jname, name);
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, pdf_new_name(ctx, pdf, name), pdf_new_string(ctx, pdf, str, strlen(str)));
	fz_always(ctx)
	{
		(*env)->ReleaseStringUTFChars(env, jstr, str);
		(*env)->ReleaseStringUTFChars(env, jname, name);
	}
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryStringPDFObject)(JNIEnv *env, jobject self, jstring jname, jobject jobj)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	pdf_obj *obj = from_PDFObject(env, jobj);
	const char *name = NULL;

	if (!ctx || !dict || !pdf || !jname || !obj)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, pdf_new_name(ctx, pdf, name), obj);
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryPDFObjectBoolean)(JNIEnv *env, jobject self, jobject jname, jboolean b)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	pdf_obj *name = from_PDFObject(env, jname);

	if (!ctx || !dict || !pdf || !name)
		return;

	fz_try(ctx)
		pdf_dict_put(ctx, dict, name, pdf_new_bool(ctx, pdf, b));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryPDFObjectInteger)(JNIEnv *env, jobject self, jobject jname, jint i)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	pdf_obj *name = from_PDFObject(env, jname);

	if (!ctx || !dict || !pdf || !name)
		return;

	fz_try(ctx)
		pdf_dict_put(ctx, dict, name, pdf_new_int(ctx, pdf, i));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryPDFObjectFloat)(JNIEnv *env, jobject self, jobject jname, jfloat f)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	pdf_obj *name = from_PDFObject(env, jname);

	if (!ctx || !dict || !pdf || !name)
		return;

	fz_try(ctx)
		pdf_dict_put(ctx, dict, name, pdf_new_real(ctx, pdf, f));
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryPDFObjectString)(JNIEnv *env, jobject self, jobject jname, jstring jstr)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	pdf_obj *name = from_PDFObject(env, jname);
	const char *str = NULL;

	if (!ctx || !dict || !pdf || !name || !jstr)
		return;

	str = (*env)->GetStringUTFChars(env, jstr, NULL);
	if (!str)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "put failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_put(ctx, dict, name, pdf_new_string(ctx, pdf, str, strlen(str)));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jstr, str);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_putDictionaryPDFObjectPDFObject)(JNIEnv *env, jobject self, jobject jname, jobject jobj)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_obj *name = from_PDFObject(env, jname);
	pdf_obj *obj = from_PDFObject(env, jobj);

	if (!ctx || !dict || !name || !obj)
		return;

	fz_try(ctx)
		pdf_dict_put(ctx, dict, name, obj);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_deleteArray)(JNIEnv *env, jobject self, jint index)
{
	fz_context *ctx = get_context(env);
	pdf_obj *arr = from_PDFObject(env, self);

	if (!ctx || !arr)
		return;

	fz_try(ctx)
		pdf_array_delete(ctx, arr, index);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_deleteDictionaryString)(JNIEnv *env, jobject self, jstring jname)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_document *pdf = dict ? pdf_get_bound_document(ctx, dict) : NULL;
	const char *name = NULL;

	if (!ctx || !dict || !pdf || !jname)
		return;

	name = (*env)->GetStringUTFChars(env, jname, NULL);
	if (!name)
	{
		jni_throw(env, FZ_ERROR_GENERIC, "delete failed");
		return;
	}

	fz_try(ctx)
		pdf_dict_del(ctx, dict, pdf_new_name(ctx, pdf, name));
	fz_always(ctx)
		(*env)->ReleaseStringUTFChars(env, jname, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT void JNICALL
FUN(PDFObject_deleteDictionaryPDFObject)(JNIEnv *env, jobject self, jobject jname)
{
	fz_context *ctx = get_context(env);
	pdf_obj *dict = from_PDFObject(env, self);
	pdf_obj *name = from_PDFObject(env, jname);

	if (!ctx || !dict || !name)
		return;

	fz_try(ctx)
		pdf_dict_del(ctx, dict, name);
	fz_catch(ctx)
		jni_rethrow(env, ctx);
}

JNIEXPORT jboolean JNICALL
FUN(PDFObject_toBoolean)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int b = 0;

	if (!ctx || !obj)
		return JNI_FALSE;

	fz_try(ctx)
		b = pdf_to_bool(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return JNI_FALSE;
	}

	return b ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jint JNICALL
FUN(PDFObject_toInteger)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	int i = 0;

	if (!ctx || !obj)
		return 0;

	fz_try(ctx)
		i = pdf_to_int(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return i;
}

JNIEXPORT jfloat JNICALL
FUN(PDFObject_toFloat)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	float f = 0;

	if (!ctx || !obj)
		return 0;

	fz_try(ctx)
		f = pdf_to_real(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return 0;
	}

	return f;
}

JNIEXPORT jobject JNICALL
FUN(PDFObject_toByteString)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	const char *str = NULL;
	jobject jbs = NULL;
	jbyte *bs = NULL;

	if (!ctx || !obj)
		return 0;

	fz_try(ctx)
		if (pdf_is_name(ctx, obj))
			str = pdf_to_name(ctx, obj);
		else
			str = pdf_to_str_buf(ctx, obj);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	jbs = (*env)->NewByteArray(env, strlen(str) + 1);
	bs = (*env)->GetByteArrayElements(env, jbs, NULL);

	memcpy(bs, str, strlen(str) + 1);

	(*env)->ReleaseByteArrayElements(env, jbs, bs, 0);

	return jbs;
}

JNIEXPORT jstring JNICALL
FUN(PDFObject_toString)(JNIEnv *env, jobject self, jboolean tight)
{
	fz_context *ctx = get_context(env);
	pdf_obj *obj = from_PDFObject(env, self);
	jstring string = NULL;
	char *s = NULL;
	int n = 0;

	if (!ctx || !obj)
		return 0;

	fz_var(s);

	fz_try(ctx)
	{
		n = pdf_sprint_obj(ctx, NULL, 0, obj, tight);
		s = fz_malloc(ctx, n + 1);
		pdf_sprint_obj(ctx, s, n + 1, obj, tight);
		string = (*env)->NewStringUTF(env, s);
	}
	fz_always(ctx)
		fz_free(ctx, s);
	fz_catch(ctx)
	{
		jni_rethrow(env, ctx);
		return NULL;
	}

	return string;
}

/* Shade interface */

JNIEXPORT void JNICALL
FUN(Shade_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	fz_shade *shd = from_Shade(env, self);

	if (!ctx || !shd)
		return;

	fz_drop_shade(ctx, shd);
}

/* PDFGraftMap interface */

JNIEXPORT void JNICALL
FUN(PDFGraftMap_finalize)(JNIEnv *env, jobject self)
{
	fz_context *ctx = get_context(env);
	pdf_graft_map *map = from_PDFGraftMap(env, self);

	if (!ctx || !map)
		return;

	pdf_drop_graft_map(ctx, map);
}
