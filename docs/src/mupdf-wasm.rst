.. Copyright (C) 2001-2023 Artifex Software, Inc.
.. All Rights Reserved.


.. include:: header.rst

.. meta::
   :description: MuPDF documentation
   :keywords: MuPDF, pdf, epub


Using :title:`MuPDF WASM`
==========================================


Installing
--------------------------------


- From the command line, select the folder you want to work from and do:

   `npm install mupdf`


- To verify your installation you can then create a :title:`JavaScript` file as such:


   .. code-block:: javascript

      const fs = require("fs");
      const mupdf = require("mupdf");
      mupdf.ready.then(function () {
         console.log(mupdf);
      });


- Save this file as "test.js".

- Then run:

   `node test.js`


- It should print the `mupdf` object along with details on the internal objects.


Loading a Document
----------------------

The following :title:`JavaScript` sample demonstrates how to load a local document and then print out the page count. Ensure you have a valid :title:`PDF` for "my_document.pdf" file alongside this :title:`JavaScript` sample before trying it.


   .. code-block:: javascript

      const fs = require("fs");
      const mupdf = require("mupdf");
      mupdf.ready.then(function () {
         var input = fs.readFileSync("my_document.pdf");
         var doc = mupdf.Document.openDocument(input, "application/pdf");
         console.log(doc.countPages());
      })


Trying the Viewer
--------------------------


From the previous installation step you should have a folder called `node_modules`. From `node_modules/mupdf/lib` copy the 3 files `mupdf-wasm.js`, `mupdf-wasm.wasm` & `mupdf.js` into `platform/wasm/lib` in your local checkout of `mupdf.git`_. Then you can open `platform/wasm/viewer/mupdf-view.html` to try it out.

.. note::

   You need to run this HTML viewer page within a suitable `Development Environment`_ in order to load and view :title:`PDFs`,
   if you see the error message "TypeError: this.mupdfWorker.openDocumentFromBuffer is not a function", please read that section.

   If running locally you can append `?file=my_file.pdf` to the browser URL to automatically load the :title:`PDF` you need without using the "Open File" option from the GUI.


Development Environment
------------------------------


Browser setup
~~~~~~~~~~~~~~~~~~

If you developing a :title:`WASM` webpage it is important to note the following pre-requisites for local development:

- You should run the webpage in a localhost environment, or:
- Run the webpage locally in a browser which allows for a less strict origin policy allowing for local file loads - see below for how to do this in :title:`Firefox`.

:title:`Artifex` recommends :title:`Firefox` as the browser of choice for local development due to its feature set of highly configurable developer options.


:title:`Firefox` - enabling local files loads
""""""""""""""""""""""""""""""""""""""""""""""""


If you are not running in a local host environment then this is required for local JS files to load & execute into the webpage without hindrance. It also allows for local :title:`PDF` files to be chosen and loaded via the `File`_ JS interface.

By default :title:`Firefox` is set to *not* allow local files to be loaded into the browser environment.

You can enable local file loads in :title:`Firefox` by setting ``security.fileuri.strict_origin_policy`` in the ``about:config`` menu to ``false``.

Steps to do this:

- Type ``about:config`` into a :title:`Firefox` tab.
- Click "Accept the Risk and Continue".
- Search for ``security.fileuri.strict_origin_policy``.
- Click on the value to toggle it to ``false``.

.. note::

   If you do this you should probably use an entirely separate browser for development use - e.g. `Firefox Developer Edition`_. Or reset the origin policy back to default at a later time.




JavaScript methodology
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Due to the asynchronous nature of a :title:`WASM` web application :title:`Web Workers` and :title:`Promises` should be used within your application to handle the life-cycle and document events.


:title:`Web Workers`
""""""""""""""""""""""""""

By utilizing :title:`Web Workers` your webpage will be able to run scripts on background threads which will not interfere with the user interface. As there may be a fair amount of file I/O and page rendering occurring the :title:`Web Worker` solution will allow for this whilst not hanging or slowing down (or seemingly crashing) your webpage.

See :title:`Mozilla's` page on `Using Web Workers`_ for more.


:title:`Promises`
""""""""""""""""""""""""""

By utilizing :title:`Promises` your :title:`JavaScript` code will be better equipped to manage asynchronous operations. Code should be easier to follow and maintain as you develop your :title:`WASM` application.


See Mozilla's page on `Using Promises`_ for more.




.. include:: footer.rst

..   External links

.. _mupdf.git: https://git.ghostscript.com/?p=mupdf.git;a=summary
.. _Disable CSP: https://stackoverflow.com/questions/27323631/how-to-override-content-security-policy-while-including-script-in-browser-js-con
.. _Disable CORS: https://stackoverflow.com/questions/17711924/disable-cross-domain-web-security-in-firefox
.. _File: https://developer.mozilla.org/en-US/docs/Web/API/File
.. _Using Web Workers: https://developer.mozilla.org/en-US/docs/Web/API/Web_Workers_API/Using_web_workers
.. _Using Promises: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_promises
.. _Firefox Developer Edition: https://www.mozilla.org/en-GB/firefox/developer/
