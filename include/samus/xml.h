/*
 * A simple XML parsing API based on Inferno's.
 * Under the surface this one uses expat and in-memory objects,
 * but that should not be visible through the API.
 */

typedef struct sa_xmlparser_s sa_xmlparser;
typedef struct sa_xmlitem_s sa_xmlitem;

fz_error *sa_openxml(sa_xmlparser **spp, fz_file *file, int ns);
void sa_debugxml(sa_xmlitem *item, int level);
void sa_closexml(sa_xmlparser *sp);

sa_xmlitem *sa_xmlnext(sa_xmlparser *sp);
void sa_xmldown(sa_xmlparser *sp);
void sa_xmlup(sa_xmlparser *sp);

int sa_isxmlerror(sa_xmlitem *item);
int sa_isxmltext(sa_xmlitem *item);
int sa_isxmltag(sa_xmlitem *item);

char *sa_xmlerror(sa_xmlitem *item);
char *sa_xmlname(sa_xmlitem *item);
char *sa_xmlatt(sa_xmlitem *item, char *att);
char *sa_xmltext(sa_xmlitem *item);

