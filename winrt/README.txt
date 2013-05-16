This MSVC project needs the thirdparty sources to be in place.

mupdf_cpp:

This is the c++ viewer code, which creates and handles the UI.

mupdfwinrt:

This defines the WinRT interface to mupdf.
There are two primary classes, mudocument and muctx.
The viewer code should create a
mudocument type and make use of the methods in
this winRT class.   The mupdocument class is a winRT
class and the methods should be callable from
C++, C#, Javascript etc.

The muctx class interfaces to the mupdf API calls
and pretty much uses standard c++ methods with
the exception of the Windows types String and Point.

mupdfwinrt lib is linked statically to the viewer
code, but this could be set up as a DLL if desired.

The libraries generated, libmupdf_winRT, libmupdf-nov8_winRT
and libthridparty_winRT are essentially the same as those
in the win32 project, however they are needed here for
building with VS 2012 ARM target.

Current Issues:

Space/Tab needs to be reworked in files

State needs to be saved during suspension

Still needs additional error checking

Needs progress bar during text search

Help info needs to be populated
