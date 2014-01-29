import java.awt.Color;
import java.awt.Paint;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Random;

import org.jfree.chart.renderer.category.BarRenderer;

class CustomRenderer extends BarRenderer {
	private Paint[] colours;

	public CustomRenderer() {
		// this.colors = new Paint[] { Color.red, Color.blue, Color.green,
		// Color.yellow, Color.orange, Color.cyan, Color.magenta,
		// Color.blue };
		this.colours = generateColours(10);
	}

	public CustomRenderer(int n) {
		this.colours = generateColours(n);
	}

	public Paint getItemPaint(final int row, final int column) {
		// returns color for each column
		return (this.colours[column % this.colours.length]);
	}

	public Color[] generateColours(int n) {
		List<Color> cols = new ArrayList<Color>(n);
		for (int i = 0; i < n; i++) {
			cols.add(Color.getHSBColor((float) i / (float) n, 0.70f, 0.9f));
		}
		Collections.shuffle(cols, new Random(1));

		return cols.toArray(new Color[cols.size()]);
	}

	public Paint[] getColours() {
		return this.colours;
	}
}