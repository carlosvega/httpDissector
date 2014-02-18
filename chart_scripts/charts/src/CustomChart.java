import java.awt.Font;
import java.awt.Paint;
import java.awt.image.BufferedImage;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartUtilities;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.LegendItem;
import org.jfree.chart.LegendItemCollection;
import org.jfree.chart.LegendItemSource;
import org.jfree.chart.StandardChartTheme;
import org.jfree.chart.axis.CategoryLabelPositions;
import org.jfree.chart.axis.LogarithmicAxis;
import org.jfree.chart.labels.StandardCategoryItemLabelGenerator;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.renderer.category.BarRenderer;
import org.jfree.chart.renderer.category.StandardBarPainter;
import org.jfree.chart.title.LegendTitle;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.xy.XYSeriesCollection;
import org.jfree.ui.HorizontalAlignment;
import org.jfree.ui.RectangleEdge;

import com.keypoint.PngEncoder;

public class CustomChart {

	private JFreeChart chart = null;
	private String title;
	private String x_axis_label;
	private String y_axis_label;
	private String filename;
	private int width;
	private int height;
	private double draw_height;
	private double draw_width;

	public CustomChart(String title, String x_axis_label, String y_axis_label,
			String filename, int width, int height) {
		this.title = title;
		this.x_axis_label = x_axis_label;
		this.y_axis_label = y_axis_label;
		this.filename = filename;
		this.width = width;
		this.height = height;
		this.draw_width = width / 2;
		this.draw_height = height / 2;
	}

	public CustomChart(String title, String x_axis_label, String y_axis_label,
			String filename, int width, int height, int draw_width,
			int draw_height) {
		this.title = title;
		this.x_axis_label = x_axis_label;
		this.y_axis_label = y_axis_label;
		this.filename = filename;
		this.width = width;
		this.height = height;
		this.draw_width = draw_width;
		this.draw_height = draw_height;
	}

	public JFreeChart getChart() {
		return chart;
	}

	public void ResponseCodeChart(DefaultCategoryDataset dataset) {
		BarRenderer.setDefaultBarPainter(new StandardBarPainter());
		ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());
		this.chart = ChartFactory.createBarChart(this.title, this.x_axis_label,
				this.y_axis_label, dataset, PlotOrientation.VERTICAL, false,
				false, false);

		this.chart.setAntiAlias(true);
		this.chart.setTextAntiAlias(true);

		this.chart.getCategoryPlot().getDomainAxis()
				.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

		BarRenderer renderer = new BarRenderer();
		renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
		renderer.setBaseItemLabelsVisible(true);
		this.chart.getCategoryPlot().setRenderer(renderer);

		LogarithmicAxis rangeAxis = new LogarithmicAxis(this.y_axis_label);
		rangeAxis.setAllowNegativesFlag(true);
		this.chart.getCategoryPlot().setRangeAxis(rangeAxis);

	}

	public void IPChart(DefaultCategoryDataset dataset) {

		BarRenderer.setDefaultBarPainter(new StandardBarPainter());
		ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());
		this.chart = ChartFactory.createBarChart(this.title, this.x_axis_label,
				this.y_axis_label, dataset, PlotOrientation.VERTICAL, false,
				false, false);

		this.chart.setAntiAlias(true);
		this.chart.setTextAntiAlias(true);

		this.chart.getCategoryPlot().getDomainAxis()
				.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

		BarRenderer renderer = new BarRenderer();
		renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
		renderer.setBaseItemLabelsVisible(true);
		this.chart.getCategoryPlot().setRenderer(renderer);

	}

	public void DomainChart(DefaultCategoryDataset dataset) {

		BarRenderer.setDefaultBarPainter(new StandardBarPainter());
		ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());
		this.chart = ChartFactory.createBarChart(this.title, this.x_axis_label,
				this.y_axis_label, dataset, PlotOrientation.VERTICAL, false,
				false, false);

		this.chart.setAntiAlias(true);
		this.chart.setTextAntiAlias(true);

		this.chart.getCategoryPlot().getDomainAxis()
				.setCategoryLabelPositions(CategoryLabelPositions.UP_45);

		BarRenderer renderer = new BarRenderer();
		renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
		renderer.setBaseItemLabelsVisible(true);
		this.chart.getCategoryPlot().setRenderer(renderer);

	}

	public void URLChart(DefaultCategoryDataset dataset, String[] url_names,
			int size) {

		BarRenderer.setDefaultBarPainter(new StandardBarPainter());
		ChartFactory.setChartTheme(StandardChartTheme.createLegacyTheme());
		this.chart = ChartFactory.createBarChart(this.title, this.x_axis_label,
				this.y_axis_label, dataset, PlotOrientation.VERTICAL, true,
				false, false);

		this.chart.setAntiAlias(true);
		this.chart.setTextAntiAlias(true);

		this.chart.removeLegend();
		final LegendItemCollection legendItemsNew = new LegendItemCollection();

		CustomRenderer renderer = new CustomRenderer(size);
		renderer.setBaseItemLabelGenerator(new StandardCategoryItemLabelGenerator());
		renderer.setBaseItemLabelsVisible(true);
		chart.getCategoryPlot().setRenderer(renderer);

		Paint[] colours = renderer.getColours();
		for (int i = 0; i < size; i++) {
			legendItemsNew.add(new LegendItem(url_names[i], colours[i]));
		}

		LegendItemSource source = new LegendItemSource() {
			LegendItemCollection lic = new LegendItemCollection();
			{
				lic.addAll(legendItemsNew);
			}

			public LegendItemCollection getLegendItems() {
				return lic;
			}
		};
		LegendTitle legend = new LegendTitle(source);
		legend.setItemFont(new Font("Arial", Font.BOLD, 12));
		legend.setHorizontalAlignment(HorizontalAlignment.CENTER);
		legend.setPosition(RectangleEdge.BOTTOM);
		this.chart.addLegend(legend);

	}

	public void CCDFChart(XYSeriesCollection dataset, double last_number) {
		this.chart = ChartFactory.createXYLineChart(this.title,
				this.x_axis_label, this.y_axis_label, dataset,
				PlotOrientation.VERTICAL, false, false, false);
		this.chart.setAntiAlias(true);
		this.chart.setTextAntiAlias(true);

		this.chart.getXYPlot().getRangeAxis().setRange(0, 1);
		LogarithmicAxis hla = new LogarithmicAxis(this.x_axis_label);
		hla.setRange(1, Math.pow(10, Math.log10(last_number) + 1));
		this.chart.getXYPlot().setDomainAxis(hla);

	}

	public void saveChart() {
		try {
			ChartUtilities.saveChartAsPNG(new File(filename), this.chart,
					this.width, this.height);
		} catch (IOException e) {
			System.out.println("Error al crear el fichero: " + this.filename);
		}
	}

	public void saveChart(int dpi) {
		BufferedImage image = this.chart.createBufferedImage(this.width,
				this.height, this.draw_width, this.draw_height, null);
		PngEncoder encoder = new PngEncoder(image, true, 0, 5);
		encoder.setDpi(dpi, dpi);
		byte[] data = encoder.pngEncode();
		BufferedOutputStream out = null;
		try {
			out = new BufferedOutputStream(new FileOutputStream(new File(
					this.filename)));
			out.write(data);
			out.close();
		} catch (FileNotFoundException e) {
			System.out.println("Couldn't create the file: " + this.filename);
		} catch (IOException e) {
			System.out.println("Couldn't write to file: " + this.filename);
		}

	}
}
