To build/debug android viewer.

NOTE: Using Android Studio.

The easiest way to get the required SDK and NDK tools is to download
and install Android Studio. While this build process does not make
use of Android Studio directly, it does neatly package the tools you
need into one easily maintainable installation. Our intention is to
move further toward Android Studio integration in the future.

1) You will need the android SDK and NDK.

The easiest way to get this is to download and install Android Studio
(see note above). If you prefer, then you can probably use a direct
download of the SDK/NDK instead.

Within Android Studio, choose: 'Configure' then 'SDK Manager' then
'Appearance and Behaviour', 'System Settings', 'Android SDK'. This
will show you the install location.

The Android Studio SDK unpacked as:

    C:\Users\UserName\AppData\Local\Android\sdk

on Windows. On MacOS it installed in:

    /Users/UserName/Library/Android/sdk

In the 'SDK Plaforms' tab, ensure that at least API 16 is
downloaded. I have a selection of later APIs too (17, 19, 22),
but these may not be required.

In the 'SDK Tools' tab, ensure that 'Android NDK' has been
selected.

Allow the system to update to ensure that everything is downloaded
correctly.

Whatever directory it unpacks to, ensure that the 'tools',
'platform-tools' and 'ndk-bundle' directories inside it have been
added to your PATH.

If you use a direct download of the ndk, then it's important that
you use the correct NDK for the target platform. If you're
targeting a 32-bit platform (such as "ARM EABI v7a" or "Intel x86
Arm") then you MUST use the 32-bit target NDK. If you get
UnsatisfiedLinkError when opening a document in MuPDF, then you've
tried to use the 64-bit target NDK with a 32-bit target!

Similary, with a direct download, it is very important that you
should unpack it to a directory with no spaces in the name! (Don't
be tempted to put it in C:\Program Files etc)

2) Previous versions of the ndk have required Cygwin to work on
windows. If you try to use a non Android Studio version, you will
need to install Cygwin 1.7 or greater now.

3) In version r5 of the ndk, when running under cygwin, there were
bugs to do with the automatic conversion of dependencies from DOS
format paths to cygwin format paths. The 2 fixes can be found in:

  <http://groups.google.com/group/android-ndk/msg/b385e47e1484c2d4>

Use the version that comes with Android Studio, and there should
not be a problem.

4) To test builds, you will either a real physical device, or
an emulated device. The SDK includes an emulator with various
different images. If you do not wish to set up an emulator,
skip this step.

From Android Studios 'Android SDK' configuration pane (see section
1 above), there is a "Launch Standalone SDK Manager" link. In
standalone sdk/ndk installations this can be reached by running
'android' from the command line. This opens the SDK configuration GUI.

In new versions of the GUI there is a 'Tools' menu from which you can
select 'Manage AVDs...'. In old versions, go to the Virtual Devices entry
on the right hand side. You need to create yourself an emulator image to
use. Click 'New...' on the right hand side and a window will appear. Fill
in the entries as follows:

     Name: FroyoEm
     Target: Android 2.2 - API Level 8
     CPU/ABI: ARM (armeabi)     (If this option exists)
     SD card: Size: 1024MiB
     Skin: Resolution: 480x756  (756 just fits my macbook screen, but 800 may
                                 be 'more standard')

Click 'Create AVD' (on old versions you may have to wait for a minute or
so while it is prepared. Now you can exit the GUI.

5) You will need a copy of the JDK installed. See
<http://www.oracle.com/technetwork/java/javase/downloads/>. When this
installs, ensure that JAVA_HOME is set to point to the installation
directory.

6) You will need a copy of Apache ANT installed.
See <http://ant.apache.org/>. Ensure that ANT_HOME is set to point to
the top level directory, and that ANT_HOME/bin is on the PATH.

7) Now we are ready to build mupdf viewer for Android. Check out a copy
of MuPDF (but you've done that already, cos you're reading this, right?).

8) You will also need a copy of mupdf's thirdparty libraries. If you are
using git, make sure to do a git submodule update --init from the top of
the build tree. Older versions packaged this source code in a .zip-file
(see the source code link on http://mupdf.com/). Unpack the contents of
this into a 'thirdparty' directory created within the mupdf directory
(i.e. at the same level as fitz, pdf, android etc).

9) Read step 10 of these instructions carefully. This is where
people skim reading invariably have problems because they skip it.

10) Finally, you will need a copy of a 'generated' directory. This is not
currently available to download.

The normal mupdf build process involves running some code on the host
(the machine on which you are compiling), rather than the target (the
machine/device on which you eventually want to run mupdf). This code
repacks various bits of information (fonts, CMAPs etc) into a more
compact and usable form.

Unfortunately, the android SDK does not provide a compiler for the host
machine, so we cannot run this step automatically as part of the android
viewer build. You will need to generate it by running a different build, such
as the windows or linux native builds.

We do not make a snapshot of the generated directory available to
download as the contents of this directory change frequently, and we'd
have to keep multiple versions on the website. We assume that anyone
capable of building for android is capable of doing a normal hosted
build.

On linux/macos, this can be as simple as running 'make generate' in the
top level directory. On Windows it's a matter of running the visual
studio solution, or of using msys or cygwin.

11) Change into mupdf's platform/android/viewer directory. Copy:

  platform/android/viewer/local.properties.sample

to be:

  platform/android/viewer/local.properties

and change the sdk path there as appropriate. This should be the only
bit of localisation you need to do.

12) Change into the platform/android/viewer directory (note,
the platform/android/viewer directory, NOT the
platform/android/viewer/jni directory!), and execute:

       ndk-build

This should build the native code portion.

If this dies with an error in thirdparty/jbig2/os_types.h load this
file into an editor, and change line 43 from:

    #else

to

    #elif !defined(HAVE_STDINT_H)

and this should solve the problem.

13) Then execute:

       ant debug

or on windows under cygwin:

       ant.bat debug

This should build the java wrapper.

14) Now, either attach your physical device, or start the emulator
by executing:

       emulator -avd FroyoEm

The emulator will take a while to start up fully (be patient).

15) We now need to give the demo file something to chew on, so let's
copy a file into the SD card image of the device (this should only
need to be done once). With the device attached (or emulator
running) type:

       adb push ../../MyTests/pdf_reference17.pdf /mnt/sdcard/Download/test.pdf

(where obviously ../../MyTests/pdf_reference17.pdf is altered for your
machine, and  under Windows, should start c:/ even if invoked from cygwin)
(adb lives in <sdk>/platform-tools if it's not on your path).

16) With the emulator running (see step 14), execute

       ant debug install

('ant.bat debug install' on Windows) and that will copy MuPDF into the
emulator where you can run it from the launchpad screen.

17) To see debug messages from the device (physical or emulated)
(including stdout/stderr from our app), execute:

       adb logcat

Good luck!
