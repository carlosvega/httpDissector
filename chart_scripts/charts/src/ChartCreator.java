import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.PriorityQueue;
import java.util.Set;

import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;

public class ChartCreator {

	private static String IP_CHART_FILENAME = "hits/ips.png";
	private static String URL_CHART_FILENAME = "hits/urls.png";
	private static String DOMAIN_CHART_FILENAME = "hits/domains.png";
	private static String CCDF_CHART_FILENAME = "stats/ccdf.png";
	private static String RESPONSE_CODES_CHART_DIR = "response_codes/";

	public ChartCreator() {
		if (main.getPath() != null) {
			String path = main.getPath();
			IP_CHART_FILENAME = path + "/" + IP_CHART_FILENAME;
			URL_CHART_FILENAME = path + "/" + URL_CHART_FILENAME;
			DOMAIN_CHART_FILENAME = path + "/" + DOMAIN_CHART_FILENAME;
			CCDF_CHART_FILENAME = path + "/" + CCDF_CHART_FILENAME;
			RESPONSE_CODES_CHART_DIR = path + "/" + RESPONSE_CODES_CHART_DIR;
		}
	}

	public void ip_chart(PriorityQueue<Entry<InetAddress, Integer>> ips) {

		System.err.println("Creating hits by IP chart...");
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();

		for (int i = 0; i < main.getTop() || ips.isEmpty(); i++) {
			Entry<InetAddress, Integer> entry = ips.poll();
			dataset.setValue((Number) entry.getValue(), 1, entry.getKey()
					.getHostAddress());
		}

		CustomChart chart = new CustomChart("Top Requests by IP", "IPs",
				"Number of Requests", IP_CHART_FILENAME, 2048, 1536);
		chart.IPChart(dataset);
		chart.saveChart(1000);

	}

	public void url_chart(PriorityQueue<Entry<String, Integer>> urls) {
		System.err.println("Creating hits by URL chart...");
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		String[] url_names = new String[main.getTop()];
		for (Integer i = 0; i < main.getTop() || urls.isEmpty(); i++) {
			Entry<String, Integer> entry = urls.poll();
			dataset.setValue((Number) entry.getValue(), 1, i.toString());
			url_names[i] = entry.getKey();
		}

		CustomChart chart = new CustomChart("Top Requests by URL", "URLs",
				"Number of Requests", URL_CHART_FILENAME, 2048, 1536);
		chart.URLChart(dataset, url_names, main.getTop());
		chart.saveChart(1000);

	}

	public void domains_chart(PriorityQueue<Entry<String, Integer>> domains) {
		System.err.println("Creating hits by Domain chart...");
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		for (Integer i = 0; i < main.getTop() || domains.isEmpty(); i++) {
			Entry<String, Integer> entry = domains.poll();
			dataset.setValue((Number) entry.getValue(), 1, entry.getKey());
		}

		CustomChart chart = new CustomChart("Top Requests by Domain",
				"Domains", "Number of Requests", DOMAIN_CHART_FILENAME, 2048,
				1536);
		chart.DomainChart(dataset);
		chart.saveChart(1000);

	}

	public void response_times_chart(
			PriorityQueue<Entry<Integer, Integer>> response_times_heap,
			long sample_size) {
		System.err.println("Creating CCDF chart...");

		XYSeriesCollection dataset = new XYSeriesCollection();
		XYSeries series = new XYSeries("CCDF");

		double suma = 0;
		double number = 0;
		response_times_heap.poll();
		while (!response_times_heap.isEmpty()) {
			Entry<Integer, Integer> entry = response_times_heap.poll();

			number = entry.getKey();
			double cant = entry.getValue();
			series.add(number, 1 - suma);
			suma += cant / sample_size;

		}
		dataset.addSeries(series);

		CustomChart chart = new CustomChart("CCDF", "Response Time (ms)", "",
				CCDF_CHART_FILENAME, 2048, 1536, 800, 600);
		chart.CCDFChart(dataset, number);
		chart.saveChart(1000);

	}

	public void response_codes_chart(
			PriorityQueue<Entry<Integer, Integer>> codes_heap,
			final HashMap<Integer, PriorityQueue<Entry<InetAddress, Integer>>> code_counters_heaps) {

		System.err.println("Creating chart for the response codes...");

		// RESPONSE CODE SUMMARY
		DefaultCategoryDataset dataset = new DefaultCategoryDataset();
		int size = codes_heap.size();
		for (int i = 0; i < size; i++) {
			Entry<Integer, Integer> entry = codes_heap.poll();
			dataset.setValue((Number) entry.getValue(), 1, entry.getKey());
		}

		CustomChart chart = new CustomChart("Response Codes", "Response Code",
				"Number of Responses", RESPONSE_CODES_CHART_DIR
						+ "ResponseCodes.png", 2048, 1536);
		chart.ResponseCodeChart(dataset);
		chart.saveChart(1000);

		final int numThreads = 8;
		final Thread[] threads = new Thread[numThreads];
		final Set<Integer> keySet = code_counters_heaps.keySet();
		final Integer[] keys = keySet.toArray(new Integer[keySet.size()]);
		for (int i = 0; i < numThreads; ++i) {
			final int thread_id = i;
			threads[i] = new Thread(new Runnable() {

				@Override
				public void run() {
					for (int i = thread_id; i < code_counters_heaps.keySet()
							.size(); i += numThreads) {
						final DefaultCategoryDataset dataset = new DefaultCategoryDataset();
						final Integer k = keys[i];
						PriorityQueue<Entry<InetAddress, Integer>> heap = code_counters_heaps
								.get(k);
						for (int j = 0; j < main.getTop() && !heap.isEmpty(); j++) {
							Entry<InetAddress, Integer> entry = heap.poll();
							dataset.setValue((Number) entry.getValue(), 1,
									entry.getKey().getHostAddress());
						}
						final CustomChart chart = new CustomChart(
								"Request with Response Code: " + k.toString(),
								"Number of Responses", "Number of Responses",
								RESPONSE_CODES_CHART_DIR + "ResponseCode_"
										+ k.toString() + ".png", 2048, 1536);
						chart.ResponseCodeChart(dataset);
						chart.saveChart(1000);
					}
				}
			});

			threads[i].start();
		}

		for (int i = 0; i < numThreads; ++i) {
			try {
				threads[i].join();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}

	}
}
