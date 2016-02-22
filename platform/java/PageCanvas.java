import com.artifex.mupdf.fitz.*;
import java.awt.*;
import java.awt.image.*;

public class PageCanvas extends java.awt.Canvas
{
	protected Page page;
	protected BufferedImage image;

	public static BufferedImage imageFromPixmap(Pixmap pixmap) {
		int w = pixmap.getWidth();
		int h = pixmap.getHeight();
		BufferedImage image = new BufferedImage(w, h, BufferedImage.TYPE_INT_ARGB);
		image.setRGB(0, 0, w, h, pixmap.getPixels(), 0, w);
		return image;
	}

	public static BufferedImage imageFromPageWithDevice(Page page, Matrix ctm) {
		Rect bbox = page.getBounds();
		Pixmap pixmap = new Pixmap(ColorSpace.DeviceBGR, bbox);
		pixmap.clear(255);
		DrawDevice dev = new DrawDevice(pixmap);
		page.run(dev, new Matrix());
		dev.destroy();
		BufferedImage image = imageFromPixmap(pixmap);
		pixmap.destroy();
		return image;
	}

	public static BufferedImage imageFromPage(Page page, Matrix ctm) {
		Pixmap pixmap = page.toPixmap(ctm, ColorSpace.DeviceBGR);
		BufferedImage image = imageFromPixmap(pixmap);
		pixmap.destroy();
		return image;
	}

	public PageCanvas(Page page_) {
		this.page = page_;
		image = imageFromPage(page, new Matrix());
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

	public void paint(Graphics g) {
		g.drawImage(image, 0, 0, null);
	}
}
