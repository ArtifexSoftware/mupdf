OS ?= $(shell uname)

ifeq "$(OS)" "Darwin"
MUPDF_JAVA := libmupdf_java.jnilib
JAVA_CFLAGS := \
	-I /Library/Java/JavaVirtualMachines/jdk1.8.0_66.jdk/Contents/Home/include \
	-I /Library/Java/JavaVirtualMachines/jdk1.8.0_66.jdk/Contents/Home/include/darwin
else
MUPDF_JAVA := libmupdf_java.so
JAVA_CFLAGS := \
	-I /usr/lib/jvm/java-7-openjdk-i386/include \
	-I /usr/lib/jvm/java-7-openjdk-i386/include/linux \
	-I /usr/lib/jvm/java-7-openjdk-amd64/include \
	-I /usr/lib/jvm/java-7-openjdk-amd64/include/linux \
	$(shell pkg-config --cflags freetype2)
JAVA_LIBS := \
	$(shell pkg-config --libs freetype2) \
	-lz
endif

default: $(MUPDF_JAVA) libmupdf.jar

MUPDF_CORE := ../../build/java/libmupdf.a ../../build/java/libmupdfthird.a
ifeq "$(OS)" "Linux"
$(MUPDF_CORE) :
	$(MAKE) -C ../.. OUT=build/java XCFLAGS=-fPIC FREETYPE_DIR=/foo ZLIB_DIR=/foo build=release libs
else
$(MUPDF_CORE) :
	$(MAKE) -C ../.. OUT=build/java XCFLAGS=-fPIC build=release libs
endif

LIBRARY_JAVA_SOURCES := $(sort $(wildcard com/artifex/mupdf/fitz/*.java))
LIBRARY_JAVA_OBJECTS := $(LIBRARY_JAVA_SOURCES:%.java=%.class)
LIBRARY_JAVA_CLASSES := $(subst com/artifex/mupdf/fitz/,com.artifex.mupdf.fitz.,$(LIBRARY_JAVA_SOURCES:%.java=%))

$(LIBRARY_JAVA_OBJECTS) : $(LIBRARY_JAVA_SOURCES)
	javac -source 1.7 -target 1.7 $^

EXAMPLE_JAVA_SOURCES := $(sort $(wildcard example/*.java))
EXAMPLE_JAVA_OBJECTS := $(EXAMPLE_JAVA_SOURCES:%.java=%.class)

$(EXAMPLE_JAVA_OBJECTS) : $(EXAMPLE_JAVA_SOURCES)
	javac -source 1.7 -target 1.7 $^

libmupdf.jar : $(LIBRARY_JAVA_OBJECTS)
	rm -f $@
	jar cf $@ $^

mupdf_native.h : $(LIBRARY_JAVA_OBJECTS)
	rm -f $@
	javah -o $@ $(LIBRARY_JAVA_CLASSES)

mupdf_native.o : mupdf_native.c mupdf_native.h
	$(CC) -g -o $@ -c $< -fPIC -Wall -Wextra -Wno-unused-parameter -I ../../include \
		$(JAVA_CFLAGS)

$(MUPDF_JAVA) : mupdf_native.o $(MUPDF_CORE)
	$(CC) -shared -o $(MUPDF_JAVA) $^ $(JAVA_LIBS)

viewer: $(MUPDF_JAVA) $(EXAMPLE_JAVA_OBJECTS)
	LD_LIBRARY_PATH=. java example.Viewer

clean:
	rm -f com/artifex/mupdf/fitz/*.class
	rm -f example/*.class
	rm -f mupdf_native.o
	rm -f $(MUPDF_JAVA)

nuke: clean
	$(MAKE) -C ../.. OUT=build/java clean

.NOTPARALLEL : # disable -j option (it breaks since javac compiles all class files in one command)
