// Enumerate historical versions of a PDF document using selectVersion().
//
// Usage: mutool run pdf-version-select.js input.pdf

var doc = Document.openDocument(scriptArgs[0]);
var pdoc = doc.asPDF();
if (!pdoc)
	throw new Error("not a PDF document");

var numVersions = pdoc.countVersions();
print("Document has " + numVersions + " version(s)");
print("Currently selected version: " + pdoc.selectedVersion());
print("");

for (var i = 0; i < numVersions; i++) {
	pdoc.selectVersion(i);
	print("Version " + i + ": " + doc.countPages() + " page(s)");
}

// Reset to latest version.
pdoc.selectVersion(0);
print("");
print("Reset to version 0 (latest): " + doc.countPages() + " page(s)");
