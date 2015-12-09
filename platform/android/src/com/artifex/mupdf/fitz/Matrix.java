package com.artifex.mupdf.fitz;

public class Matrix
{
	public float a;
	public float b;
	public float c;
	public float d;
	public float e;
	public float f;

	public Matrix(float a, float b, float c, float d, float e, float f)
	{
		this.a = a;
		this.b = b;
		this.c = c;
		this.d = d;
		this.e = e;
		this.f = f;
	}

	public Matrix(float a, float d)
	{
		this.a = a;
		this.b = 0;
		this.c = 0;
		this.d = d;
		this.e = 0;
		this.f = 0;
	}

	public Matrix(float a)
	{
		this.a = a;
		this.b = 0;
		this.c = 0;
		this.d = a;
		this.e = 0;
		this.f = 0;
	}

	public Matrix concat(Matrix m)
	{
		float a = this.a * m.a + this.b * m.c;
		float b = this.a * m.b + this.b * m.d;
		float c = this.c * m.a + this.d * m.c;
		float d = this.c * m.b + this.d * m.d;
		float e = this.e * m.a + this.f * m.c + m.e;
		this.f = this.e * m.b + this.f * m.d + m.f;

		this.a = a;
		this.b = b;
		this.c = c;
		this.d = d;
		this.e = e;

		return this;
	}
}
