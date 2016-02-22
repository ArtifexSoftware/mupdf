default: libmupdf_java.so libmupdf.jar

MUPDF_CORE = ../../build/java/libmupdf.a ../../build/java/libmupdfthird.a

LIBRARY_JAVA_SOURCES := $(sort $(wildcard com/artifex/mupdf/fitz/*.java))
LIBRARY_JAVA_OBJECTS := $(LIBRARY_JAVA_SOURCES:%.java=%.class)
LIBRARY_JAVA_CLASSES := $(subst com/artifex/mupdf/fitz/,com.artifex.mupdf.fitz.,$(LIBRARY_JAVA_SOURCES:%.java=%))

VIEWER_JAVA_SOURCES := $(sort $(wildcard *.java))
VIEWER_JAVA_OBJECTS := $(VIEWER_JAVA_SOURCES:%.java=%.class)

$(MUPDF_CORE) :
	$(MAKE) -C ../.. OUT=build/java XCFLAGS=-fPIC build=release libs

$(LIBRARY_JAVA_OBJECTS) : $(LIBRARY_JAVA_SOURCES)
	javac $^

libmupdf.jar : $(LIBRARY_JAVA_OBJECTS)
	rm -f $@
	jar cf $@ $^

mupdf_native.h : $(LIBRARY_JAVA_OBJECTS)
	rm -f $@
	javah -o $@ $(LIBRARY_JAVA_CLASSES)

mupdf_native.o : mupdf_native.c mupdf_native.h
	$(CC) -g -fPIC -Wall -Wextra -Wno-unused-parameter \
		-I /usr/lib/jvm/java-7-openjdk-amd64/include \
		-I /usr/lib/jvm/java-7-openjdk-amd64/include/linux \
		-I ../../include \
		-o $@ -c $<

libmupdf_java.so : mupdf_native.o $(MUPDF_CORE)
	$(CC) -shared -o $@ $^ -lcrypto

$(VIEWER_JAVA_OBJECTS) : $(VIEWER_JAVA_SOURCES)
	javac $^

viewer: libmupdf_java.so $(LIBRARY_JAVA_OBJECTS) $(VIEWER_JAVA_OBJECTS)
	LD_LIBRARY_PATH=. java Viewer

clean:
	rm -f com/artifex/mupdf/fitz/*.class
	rm -f *.class
	rm -f mupdf_native.o
	rm -f libmupdf_java.so

nuke: clean
	$(MAKE) -C ../.. OUT=build/java clean

.NOTPARALLEL : # disable -j option (it breaks since javac compiles all class files in one command)
