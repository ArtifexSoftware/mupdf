mupdf/platform/android/example - build instructions

1.  get the code and submodules

2.  make generate

3.  cd mupdf/platform/android/viewer

3.  build:   ndk-build

4.  copy the resulting .so file:

	mkdir -p ../example/mupdf/libs/armeabi-v7a
	rm -f ../example/mupdf/libs/armeabi-v7a/libmupdf_java32.so
	cp ./libs/armeabi-v7a/libmupdf_java.so ../example/mupdf/libs/armeabi-v7a/

5.  Open the example in Android Studio

6.  build and run

If you modify C code, do steps 3, 4 and 6 as needed
