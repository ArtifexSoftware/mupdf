# Template documentation

Welcome to the MuPDF WASM documentation. This documentation relies on [Sphinx](https://www.sphinx-doc.org/en/master/) to publish HTML docs from markdown files written with [restructured text](https://en.wikipedia.org/wiki/ReStructuredText) (RST).

## Sphinx version

This README assumes you have [Sphinx v5.0.2 installed](https://www.sphinx-doc.org/en/master/usage/installation.html) on your system.


## Updating the documentation

Within the "docs" folder update the associated restructured text (`.rst`) files. These files represent the corresponding document pages.



## Building HTML documentation

- Ensure you have the `sphinx-rtd-theme` installed:


`python -m pip install sphinx-rtd-theme`


- From the "docs" location run:

`sphinx-build -b html src build`


This then creates the HTML documentation within the folder "build" in the root of "docs".


## Building PDF documentation


- First ensure you have [rst2pdf](https://pypi.org/project/rst2pdf/) installed:


`python -m pip install rst2pdf`


- Then run:


`sphinx-build -b pdf . build/pdf`

This will then generate a single PDF for all of the documentation within `build/pdf`.


---


For full details see: [Using Sphinx](https://www.sphinx-doc.org/en/master/usage/index.html)
