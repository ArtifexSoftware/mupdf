// usage: ctags -x --sort=no --kinds-c=dfgpstux include/mupdf/whatever.h | node scripts/docs/header.js > docs/whatever.md

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

function is_header_guard(file, tag) {
	return (tag.type === "macro" && file.replace("include/", "").toUpperCase().replace(/[/\.-]/g, "_") === tag.symbol)
}

function slugify(id) {
	if (is_sphinx)
		return id.toLowerCase().replace(/[^\w\-\./ ]/g, "").replace(/[^a-z0-9\-]/g, "-")
	return id.toLowerCase().replace(/[^\w\- ]/g, "").replace(/ /g, "-")
}

function anchor_from_tag(tag) {
	return "#" + slugify(tag.type + "-" + tag.symbol)
}

var all_tags = []
var all_files = []

fs.readFileSync(0, "utf-8").split("\n").filter(x => x.length > 0).forEach(line => {
	var seen_symbol = {}
	var [ symbol, type, line, file ] = line.split(/\s+/)
	if (type === "member")
		return
	if (symbol.startsWith("__anon"))
		return
	if (type === "externvar") type = "global"
	if (type === "prototype") type = "function"
	if (seen_symbol[type + ":" + symbol])
		console.error("duplicate " + type + " " + symbol)
	else
		seen_symbol[type + ":" + symbol] = 1
	all_tags.push({ type, symbol, file, line, comments: [] })
	if (!all_files.includes(file))
		all_files.push(file)
})

// Remove leading lines of stars or initial indentation from block comment
function clean_comment(lines) {
	// strip /** and */
	lines[0] = lines[0].replace("/**/", "")
	lines[0] = lines[0].replace(/^\/\*\*?\s*/, "")
	lines[lines.length-1] = lines[lines.length-1].replace(/\s*\*\/.*/, "")

	// remove leading and trailing blank lines
	while (lines.length > 0 && lines[0].length === 0) lines.shift()
	while (lines.length > 0 && lines[lines.length-1].length === 0) lines.pop()

	// remove initial tab indent (if present)
	if (lines.every(x => x === "" || x.startsWith("\t")))
		lines = lines.map(x => x.replace(/^\t/, ""))

	// remove left edge stars (if present)
	else if (lines.slice(1).every(x => x.startsWith(" *")))
		lines = lines.map(x => x.replace(/^ \* ?/, ""))
	else if (lines.slice(1).every(x => x.startsWith("*")))
		lines = lines.map(x => x.replace(/^\* ?/, ""))

	// remove leading and trailing blank lines (again)
	while (lines.length > 0 && lines[0].length === 0) lines.shift()
	while (lines.length > 0 && lines[lines.length-1].length === 0) lines.pop()

	lines = lines.join("\n")

	// Convert simple definition lists into the awkward markdown syntax:
	// multi-line definitions: "word(, word):\n\tline one\n\tline two..."
	lines = lines.replace(/^([a-z]\w+(, \w+)*):\n((\t.+\n?)+)/mg, "$1:\n:$3\n")
	// single line definitions "word: a single line.\n"
	lines = lines.replace(/^([a-z]\w*(, \w+)*): (.+)\n?/mg, "$1:\n: $3\n")

	return lines
}

function reformat_prototype(text) {
	var m = text.replaceAll("\n", " ").match(/^(.*?)([_A-Za-z0-9]+)\s*\(([^(]*)\)$/)
	if (m) {
		var p_return = m[1].trim()
		//if (!p_return.endsWith("*")) p_return = p_return + " "
		var p_name = m[2]
		var p_args = m[3].trim()
		if (p_args.length > 0) {
			p_args = p_args.split(",").map(arg => arg.trim())
			return p_return + "\n" + p_name + " (\n\t" + p_args.join(",\n\t") + "\n)"
		}
		return p_return + "\n" + p_name + " ()"
	}
	return text
}

// Extract associated code chunk for a symbol (struct and enum body, function signature, etc)
function extract_code(type, lines, first_line) {
	function extract_block(s) {
		for (var x = 0, i = 0; i < s.length; ++i) {
			if (s[i] === ';' && x === 0)
				return s.slice(0, i)
			if (s[i] === '{') ++x
			if (s[i] === '}') --x
		}
		return "ERROR"
	}

	function extract_function(s) {
		for (var x = 0, i = 1; i < s.length; ++i) {
			if (s[i] === '(') ++x
			if (s[i] === ')') {
				if (--x === 0)
					return s.slice(0, i+1)
			}
		}
		return "ERROR"
	}

	function extract_macro(s) {
		for (var x = 0, i = 1; i < s.length; ++i) {
			if (s[i] === '\n' && s[i-1] !== '\\')
				return s.slice(0, i)
			if (s[i] === '(') ++x
			if (s[i] === ')') {
				if (--x === 0)
					return s.slice(0, i+1)
			}
		}
		return "ERROR"
	}

	// include return type in two-line declarations "int\nfunction foo(...)"
	if (type === "function" && !(/(;|\*\/|\/\/)/.test(lines[first_line-1])))
		--first_line

	var code = lines.slice(first_line).join("\n")

	if (type === "global")
		code = code.replace("FZ_DATA ", "")

	if (type === "function") {
		code = extract_function(code)
		code = code.replace("FZ_NORETURN", "[[noreturn]]")
		code = code.replace(/static( inline)? /, "")
		if (1) {
			code = reformat_prototype(code)
		} else {
			// merge two-line declarations
			if (!code.split("\n")[0].includes("(")) {
				if (code.split("\n")[0].endsWith("*"))
					code = code.replace("\n", "")
				else
					code = code.replace("\n", " ")
			}
		}
		return code
	}

	if (type === "macro")
		return extract_macro(code)

	if (type === "function" || type === "typedef")
		return code.replace(/([^;]*);[\s\S]*/m, "$1")

	code = extract_block(code)
	if (type !== "typedef" && code.startsWith("typedef "))
		code = code.replace(/^typedef /, "").replace(/} \w+$/, "}")
	return code
}

function process_file(file) {
	var tags = all_tags.filter(tag => tag.file === file)
	var comments = []
	var typedefs = {}
	var seen_symbol

	var lines = fs.readFileSync(file, "utf-8").split("\n")

	// extract code definitions
	tags.forEach(tag => {
		tag.code = extract_code(tag.type, lines, tag.line-1)
		if (tag.type === "enum" || tag.type === "struct")
			typedefs[tag.symbol] = true
	})

	// extract top-level comments
	var text = null
	lines.forEach((line,ix) => {
		if (line.startsWith("/*"))
			text = []
		if (text) {
			text.push(line)
			if (line.endsWith("*/")) {
				comments.push({ type: "comment", line: ix+1, text: clean_comment(text) })
				text = null
			}
		}
	})

	// interleave comments and symbols in the original file order
	var chunks = tags.concat(comments).sort((a,b) => a.line - b.line)

	// add sentinel
	chunks.push({ type: "comment", text: "" })

	// emit markdown

	print("# " + file.replace("include/mupdf/", ""))
	print("")

	// emit table of content
	if (!is_sphinx) {
		print("## Index")
		seen_symbol = {}
		var subheader = null
		for (var tag of tags.sort((a, b) => type_sort[a.type] + a.symbol < type_sort[b.type] + b.symbol ? -1 : 1)) {
			if (seen_symbol[tag.type + tag.symbol])
				continue
			seen_symbol[tag.type + tag.symbol] = 1
			if (is_header_guard(file, tag))
				continue
			if (tag.type === "typedef" && typedefs[tag.symbol])
				continue
			if (tag.type !== subheader) {
				print("")
				print("### " + tag.type)
				subheader = tag.type
			}
			print(`- [${tag.symbol}](${anchor_from_tag(tag)})`)
		}
		print("")
	}

	function emit_tag(tag, attach) {
		if (seen_symbol[tag.type + tag.symbol] && !attach)
			return
		seen_symbol[tag.type + tag.symbol] = 1
		print(`### ${tag.type} [${tag.symbol}](${anchor_from_tag(tag)})`)
		print("")
		print("\t" + tag.code.split("\n").join("\n\t"))
		print("")
		if (attach)
			emit_comment(attach)
	}

	function emit_comment(text) {
		print(text)
		print("")
	}

	if (chunks[0].type !== "comment" || !chunks[0].text.startsWith("#")) {
		// TODO: print("## Public")
		var title = file.replace(/.*\//, "").split(".")[0].split("-").map(word => word[0].toUpperCase() + word.slice(1)).join(" ")
		print("## " + title)
		print("")
	}

	seen_symbol = {}
	for (var i = 0; i < chunks.length - 1; ++i) {
		var a = chunks[i]
		var b = chunks[i+1]
		if (a.type === "comment") {
			if (a.text.trim().startsWith("#")) {
				emit_comment(a.text)
			} else if (b.type !== "comment") {
				if (is_header_guard(file, b))
					emit_comment(a.text)
				else
					emit_tag(b, a.text)
				++i
			} else {
				emit_comment(a.text)
			}
		} else {
			// filter out header guard macros
			if (is_header_guard(file, a))
				continue
			// filter out comment-less typedefs where there is a struct or enum defined
			if (a.type === "typedef" && typedefs[a.symbol])
				continue
			emit_tag(a, null)
		}
	}
}

all_files.forEach(process_file)
