/* C++ version of the pdf_jsimp api. C++ cannot safely call fz_throw,
 * so C++ implementations return explicit errors in char * form. */


fz_context *pdf_jsimp_ctx_cpp(pdf_jsimp *imp);
char *pdf_new_jsimp_cpp(fz_context *ctx, void *jsctx, pdf_jsimp **imp);
char *pdf_drop_jsimp_cpp(pdf_jsimp *imp);
char *pdf_jsimp_new_type_cpp(pdf_jsimp *imp, pdf_jsimp_dtr *dtr, pdf_jsimp_type **type);
char *pdf_jsimp_drop_type_cpp(pdf_jsimp *imp, pdf_jsimp_type *type);
char *pdf_jsimp_addmethod_cpp(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_method *meth);
char *pdf_jsimp_addproperty_cpp(pdf_jsimp *imp, pdf_jsimp_type *type, char *name, pdf_jsimp_getter *get, pdf_jsimp_setter *set);
char *pdf_jsimp_set_global_type_cpp(pdf_jsimp *imp, pdf_jsimp_type *type);
char *pdf_jsimp_new_obj_cpp(pdf_jsimp *imp, pdf_jsimp_type *type, void *natobj, pdf_jsimp_obj **obj);
char *pdf_jsimp_drop_obj_cpp(pdf_jsimp *imp, pdf_jsimp_obj *obj);
char *pdf_jsimp_fromString_cpp(pdf_jsimp *imp, char *str, pdf_jsimp_obj **obj);
char *pdf_jsimp_toString_cpp(pdf_jsimp *imp, pdf_jsimp_obj *obj, char **str);
char *pdf_jsimp_execute_cpp(pdf_jsimp *imp, char *code);
char *pdf_jsimp_execute_count_cpp(pdf_jsimp *imp, char *code, int count);
