package example;

import com.artifex.mupdf.fitz.*;
import java.awt.*;
import java.awt.image.*;

public class PageCanvas extends java.awt.Canvas
{
	protected Page page;
	protected BufferedImage image;

	protected float mScale = 1.0f;
	private float mRetinaScale = 1.0f;

	public static BufferedImage imageFromPixmap(Pixmap pixmap) {
		int w = pixmap.getWidth();
		int h = pixmap.getHeight();
		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		image.setRGB(0, 0, w, h, pixmap.getPixels(), 0, w);
		return image;
	}

	public static BufferedImage imageFromPageWithDevice(Page page, Matrix ctm) {
		Rect bbox = page.getBounds();
		bbox.transform(ctm);
		Pixmap pixmap = new Pixmap(ColorSpace.DeviceBGR, bbox);
		pixmap.clear(255);
		DrawDevice dev = new DrawDevice(pixmap);
		page.run(dev, ctm);
		dev.destroy();
		BufferedImage image = imageFromPixmap(pixmap);
		pixmap.destroy();
		return image;
	}

	public static BufferedImage imageFromPage(Page page, Matrix ctm) {
		Pixmap pixmap = page.toPixmap(ctm, ColorSpace.DeviceBGR, true);
		BufferedImage image = imageFromPixmap(pixmap);
		pixmap.destroy();
		return image;
	}

	public PageCanvas(Page page_, float nativeScale) {
		mRetinaScale = nativeScale;
		mScale = mRetinaScale;
		this.page = page_;
		run();
	}

	private void run()
	{
		Matrix ctm = new Matrix();
		ctm.scale(mScale);
		image = imageFromPage(page, ctm);
		repaint();
	}

	public Dimension getPreferredSize() {
		return new Dimension(image.getWidth(), image.getHeight());
	}

	public Dimension getMinimumSize() {
		return getPreferredSize();
	}

	public Dimension getMaximumSize() {
		return getPreferredSize();
	}

	public void zoomIn() {
		mScale += 0.25f;
		run();
	}

	public void zoomOut() {
	    mScale -= 0.25f;
	    run();
	}

	public void paint(Graphics g)
	{
		float scale = 1.0f;
		scale = 1/mRetinaScale;

		final Graphics2D g2d = (Graphics2D)g.create(0, 0, image.getWidth(), image.getHeight());
		g2d.scale(scale, scale);
		g2d.drawImage(image, 0, 0, null);
		g2d.dispose();
	}

}
