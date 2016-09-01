package com.artifex.mupdf.fitz;

public class Separation
{
	public String name;
	public int rgba;
	public int cmyk;

	public Separation(String name, int rgba, int cmyk)
	{
		this.name = name;
		this.rgba = rgba;
		this.cmyk = cmyk;
	}
}
