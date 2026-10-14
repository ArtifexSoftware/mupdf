// usage: ctags -x --sort=yes --kinds-c=dfgpstux include/mupdf/*/*.h | node scripts/docs/index.js > docs/index.md

"use strict"

const fs = require("fs")
const print = console.log
const is_sphinx = process.argv.includes("--sphinx")

const type_sort = {
	typedef: 0,
	struct: 1,
	enum: 2,
	macro: 3,
	global: 4,
	function: 5,
}

function is_header_guard(tag) {
	return (tag.type === "macro" && tag.real_file.replace("include/", "").toUpperCase().replace(/[/\.-]/g, "_") === tag.symbol)
}

function slugify(id) {
	if (is_sphinx)
		return id.toLowerCase().replace(/[^\w\-\./ ]/g, "").replace(/[^a-z0-9\-]/g, "-")
	return id.toLowerCase().replace(/[^\w\- ]/g, "").replace(/ /g, "-")
}

function link_from_tag(tag) {
	return tag.file.replace("include/mupdf/", "").replace(".h", ".md") + "#" + slugify(tag.type + "-" + tag.symbol)
}

function link_from_file(file) {
	return file.replace("include/mupdf/", "").replace(".h", ".md")
}

var all_tags = []
var all_files = []
var seen_enum_or_struct = {}
var seen_symbol = {}

fs.readFileSync(0, "utf-8").split("\n").filter(x => x.length > 0).forEach(line => {
	var [ symbol, type, line, real_file ] = line.split(/\s+/)
	if (symbol.startsWith("__anon"))
		return
	var file = real_file.replace("include/mupdf/", "")
	if (type === "externvar") type = "global"
	if (type === "prototype") type = "function"
	if (!seen_symbol[file + type + symbol])
		all_tags.push({ type, symbol, file, real_file, line, comments: [] })
	seen_symbol[file + type + symbol] = 1
	if (type === "enum" || type === "struct")
		seen_enum_or_struct[symbol] = true
	if (!all_files.includes(file))
		all_files.push(file)
})

all_files.sort()

all_tags = all_tags.filter(tag => {
	// remove enum/struct typedefs
	if (is_header_guard(tag))
		return false
	// remove typedefs of named enums and structs
	if (tag.type === "typedef" && seen_enum_or_struct[tag.symbol])
		return false
	return true
})

print("# MuPDF C Library Index")
print("")

print("## Files")
print("")
all_files.forEach(file => print(`- [${file}](${file.replace(".h", ".md")})`))
print("")

print("## Symbols")
print("")
all_tags.forEach(tag => {
	print(`- [${tag.symbol}](${link_from_tag(tag)}) (${tag.file})`)
})
