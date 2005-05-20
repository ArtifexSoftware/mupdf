/*
 * XML mini-dom based on Inferno's XML parser API.
 * This one uses expat and in-memory objects though... :(
 */

typedef struct sa_xmlnode_s sa_xmlnode;

fz_error *sa_parsexml(sa_xmlnode **nodep, fz_file *file, int ns);
void sa_debugxml(sa_xmlnode *node, int level);
void sa_dropxml(sa_xmlnode *node);

sa_xmlnode *sa_xmlup(sa_xmlnode *node);
sa_xmlnode *sa_xmlnext(sa_xmlnode *node);
sa_xmlnode *sa_xmldown(sa_xmlnode *node);

int sa_isxmltext(sa_xmlnode *node);
int sa_isxmltag(sa_xmlnode *node);

char *sa_getxmlname(sa_xmlnode *node);
char *sa_getxmlatt(sa_xmlnode *node, char *att);
char *sa_getxmltext(sa_xmlnode *node);

