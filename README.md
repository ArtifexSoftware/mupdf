### *mupdf-x11* - A very fast pdf viewer (for Linux)!

I've fixed and enhanced the keyboard interface:

 - [number] **Space**: scroll down till bottom, next page [jump to page]
 - **Backspace**: scroll up to top, previous page
 - **End**: goto last page
 - **Home**: goto first page
 - [number] **Page_Down**: top of next page [jump forward]
 - [number] **Page_Up**: top of previous page [jump backward]
 - **Up, Down, Left, Right**: in-page scroll
 - **,**: -5 pages
 - **.**: +5 pages
 - **Tab**: toggle smartmove
 - **Enter**: load dirpage
 - **d**: save dirpage
 - **#**: (extra) zoom in
 - **Escape**: quit

    *dirpage* ==> provides a favorite/directory page
    (defaults to 1 or the page parameter)

    *smartmove* ==> keep pan position with page change


*Build*:

```
git clone --branch update --recurse-submodules https://github.com/linuxCowboy/mupdf.git

sudo apt install xorg-dev

cd mupdf; make HAVE_GLUT=no

cp build/release/mupdf-x11 ~/bin/mupdf

mupdf ct-magazine.pdf 6
```

-----

ABOUT

MuPDF is a lightweight open source software framework for viewing and converting
PDF, XPS, and E-book documents.

See the documentation in docs/index.html for an overview.

Build instructions can be found in docs/building.html.

LICENSE

MuPDF is Copyright (c) 2006-2017 Artifex Software, Inc.

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU Affero General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU Affero General Public License along
with this program. If not, see <http://www.gnu.org/licenses/>.

For commercial licensing, including our "Indie Dev" friendly options,
please contact sales@artifex.com.

REPORTING BUGS AND PROBLEMS

The MuPDF developers hang out on IRC in the #mupdf channel on irc.freenode.net.

Report bugs on the ghostscript bugzilla, with MuPDF as the selected component.

	http://bugs.ghostscript.com/

If you are reporting a problem with a specific file, please include the file as
an attachment.
