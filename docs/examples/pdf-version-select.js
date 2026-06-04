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
	print("Version " + i + ": " + doc.countPages() + " page(s)"
		+ " (selectedVersion=" + pdoc.selectedVersion() + ")");
}

// Reset to latest version.
pdoc.selectVersion(0);
print("");
print("Reset to version 0 (latest): " + doc.countPages() + " page(s)");

// Demonstrate error handling for out-of-range version.
print("");
try {
	pdoc.selectVersion(numVersions);
	print("ERROR: out-of-range selectVersion did not throw");
} catch (e) {
	print("Out-of-range version correctly rejected: " + e);
}

// Demonstrate that modifications are rejected during historical view.
pdoc.selectVersion(1);
try {
	pdoc.createObject();
	print("ERROR: createObject during historical view did not throw");
} catch (e) {
	print("Modification during historical view correctly rejected: " + e);
}

// Demonstrate that save is rejected during historical view.
try {
	pdoc.save("/dev/null");
	print("ERROR: save during historical view did not throw");
} catch (e) {
	print("Save during historical view correctly rejected: " + e);
}

pdoc.selectVersion(0);
print("Restored to version 0 after error handling demos");
