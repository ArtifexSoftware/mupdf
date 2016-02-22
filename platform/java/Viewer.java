import com.artifex.mupdf.fitz.*;
import java.awt.Frame;
import java.awt.Label;
import java.awt.BorderLayout;
import java.awt.event.*;

public class Viewer extends Frame implements WindowListener
{
	protected Document doc;
	protected PageCanvas pageCanvas;
	protected Label pageLabel;
	protected int count;

	public Viewer(Document doc_) {
		super("MuPDF");

		this.doc = doc_;
		this.count = doc.countPages();

		setSize(600, 900);

		pageCanvas = new PageCanvas(doc.loadPage(1144));
		pageLabel = new Label("page " + 1);

		add(pageLabel, BorderLayout.NORTH);
		add(pageCanvas, BorderLayout.CENTER);

		addWindowListener(this);

		{
			Page page = doc.loadPage(0);
			Device dev = new Device() {
				public void beginPage(Rect r, Matrix m) {
					System.out.println("beginPage " + r + m);
				}
				public void fillText(Text text, Matrix ctm, ColorSpace cs, float color[], float alpha) {
					System.out.println("fillText " + text);
					text.walk(new TextWalker() {
						public void showGlyph(Font f, boolean v, Matrix m, int g, int c) {
							System.out.println(f + " " + m + " " + g + " " + (char)c);
						}
					});
				}
			};
			page.run(dev, new Matrix(), null);
		}
	}

	// WindowListener

	public void windowClosing(WindowEvent event) {
		System.exit(0);
	}

	public void windowActivated(WindowEvent event) { }
	public void windowDeactivated(WindowEvent event) { }
	public void windowIconified(WindowEvent event) { }
	public void windowDeiconified(WindowEvent event) { }
	public void windowOpened(WindowEvent event) { }
	public void windowClosed(WindowEvent event) { }

	public static void main(String[] args) {
		Document doc = new Document("pdfref17.pdf");
		Viewer app = new Viewer(doc);
		app.setVisible(true);
	}
}
