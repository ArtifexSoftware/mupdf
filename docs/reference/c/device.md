# Device

The device interface is how we provide access to the contents of a document. A
device is a callback structure, that gets called for each piece of text, line
art, and image on a page. There are several device implementations. The most
important one renders the contents to a raster image, and another one gathers
all the text into a structure that can be used to select and copy and search
the text content on a page.
