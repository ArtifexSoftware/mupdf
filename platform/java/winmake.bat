@echo Cleaning
echo bogus > example\bogus.class
del /Q example\*.class
echo bogus > com\artifex\mupdf\fitz\bogus.class
del /Q com\artifex\mupdf\fitz\*.class

@echo Building Viewer
javac -source 1.7 -target 1.7 example/Viewer.java

@echo Building JNI classes
javac -source 1.7 -target 1.7 com/artifex/mupdf/fitz/*.java

@echo Importing DLL (built using VS solution)
@copy ..\win32\%1\javaviewerlib.dll mupdf_java.dll /y

@echo Packaging into jar (incomplete as missing manifest)
jar cf mupdf-java-viewer.jar mupdf_java.dll com\artifex\mupdf\fitz\*.class example\*.class
