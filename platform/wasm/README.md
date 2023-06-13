<img src="https://mupdf.readthedocs.io/en/latest/_images/mupdf-icon.png" width="96px" height="96px">

# MuPDF.js

This is a build of MuPDF targeting WASM environments from Artifex Software, the creators of MuPDF.

This library can be used both in browsers and in Node via a JavaScript module.


## Getting started


From the command line, select the folder you want to work from and do:

`npm install mupdf`

To verify your installation you can then create a JavaScript file as such:

```
const fs = require("fs");
const mupdf = require("mupdf");
mupdf.ready.then(function () {
   console.log(mupdf);
});
```

Save this file as “test.js”.

Then, on the command line, run:

`node test.js`

This will print the `mupdf` object, along with details on the internal objects, to the console.


## Loading a document

The following JavaScript sample demonstrates how to load a local document and then print out the page count. Ensure you have a valid PDF for the "my_document.pdf" file alongside this JavaScript sample before trying it.

```
const fs = require("fs");
const mupdf = require("mupdf");
mupdf.ready.then(function () {
   var input = fs.readFileSync("my_document.pdf");
   var doc = mupdf.Document.openDocument(input, "application/pdf");
   console.log(doc.countPages());
})
```


## License

AGPLv3 or above, subject to the [MuPDF license](https://www.mupdf.com/licensing/).



## Documentation

For full documentation and API please refer to [MuPDF on Read the Docs](https://mupdf.readthedocs.io).
