package com.artifex.mupdf.fitz;

public class Outline
{
	public String title;
	public String uri;
	public int page;
	public Outline down[];

	public Outline(String title, int page, String uri, Outline[] down) {
		this.title = title;
		this.page = page;
		this.uri = uri;
		this.down = down;
	}

	public String toString()
	{
		StringBuffer s = new StringBuffer();

		s.append(page);
		s.append(": ");
		s.append(title);
		s.append(' ');
		s.append(uri);
		s.append('\n');

		if (down != null)
		{
			for (int i = 0; i < down.length; i++)
			{
				s.append('\t');
				s.append(down[i]);
				s.append('\n');
			}
		}

		s.deleteCharAt(s.length() - 1);

		return s.toString();
	}

}
