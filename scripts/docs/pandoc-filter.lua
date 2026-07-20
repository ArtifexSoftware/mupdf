local title = nil

-- extract first h1 as title
function Header (h)
	if h.level == 1 and not title then
		title = h.content
		return {}
	end
	return h
end

function Meta(m)
	if not m.title then
		m.title = title
	end
	return m
end

-- remove explicit column widths set by pandoc
function Table (tbl)
	tbl.colspecs = tbl.colspecs:map(
		function (colspec)
			local align = colspec[1]
			local width = nil  -- default width
			return {align, width}
		end
	)
	return tbl
end

-- change markdown links to html
function Link (e)
	e.target = string.gsub(e.target, "%.md", ".html")
	return e
end
