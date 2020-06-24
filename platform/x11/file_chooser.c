/* Shows file chooser dialog and returns selected file.
 * THIS IS A STUB. FEEL FREE TO CHANGE AS YOU SEE FIT.
 * Compile: 
 * sudo apt install libgtk2.0-dev
 * gcc -Wl,--no-as-needed `pkg-config --cflags --libs gtk+-2.0` file_chooser.c -o file_chooser */

#include <gtk/gtk.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libgen.h>
#include <dirent.h>


int main(int argc, char *argv[])
{
    gchar *path;
    GtkWidget *dialog;
    int dlg_ret = 0;

    char command[255];
    char *dir = realpath( "/proc/self/exe", NULL );
    if (!dir)
    {
        exit(1);
    }

    sprintf(command, "%s/mupdf-gl", dirname(dir));

    gtk_init(&argc, &argv);
    dialog = gtk_file_chooser_dialog_new("Select file", NULL, GTK_FILE_CHOOSER_ACTION_OPEN, GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL, GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT, NULL);
    dlg_ret = gtk_dialog_run(GTK_DIALOG(dialog));
    if(dlg_ret == GTK_RESPONSE_ACCEPT)
    {
	path = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
        if( path!=NULL )
        {
            return execlp(command, command, path, NULL);
        }
    }
    gtk_widget_destroy(dialog);
    gtk_exit(0);
    return 0;
}
