import java.net.InetAddress;
import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import java.util.PriorityQueue;

public class DataParser {

	private ChartCreator chartCreator = null;
	private CounterComparator<String> comparator = null;
	private CounterComparator<InetAddress> comparatorIP = null;
	private String path = null;

	public DataParser(String path) {
		this.path = path;
		chartCreator = new ChartCreator(path);
		comparator = new CounterComparator<String>();
		comparatorIP = new CounterComparator<InetAddress>();
	}

	public DataParser() {
		chartCreator = new ChartCreator();
		comparator = new CounterComparator<String>();
		comparatorIP = new CounterComparator<InetAddress>();
	}

	public void parse_flowprocess_conections(Counter<Integer> conections_per_sec) {
		// ORDER SECS
		CounterComparatorByKey<Integer> comparator = new CounterComparatorByKey<Integer>();
		PriorityQueue<Entry<Integer, Integer>> secs_heap = new PriorityQueue<Map.Entry<Integer, Integer>>(
				conections_per_sec.size() + 1, comparator);
		secs_heap.addAll(conections_per_sec.getDictionary().entrySet());

		chartCreator.flowprocess_chart(secs_heap);
		secs_heap.clear();
		secs_heap = null;
	}

	public void parse_ip_hits(Counter<InetAddress> ips) {

		// ORDER IPS
		PriorityQueue<Entry<InetAddress, Integer>> ips_heap = new PriorityQueue<Map.Entry<InetAddress, Integer>>(
				20, comparatorIP);
		ips_heap.addAll(ips.getDictionary().entrySet());

		chartCreator.ip_chart(ips_heap);
		ips_heap.clear();
		ips_heap = null;
	}

	public void parse_url_hits(Counter<String> urls) {

		// ORDER URLS
		PriorityQueue<Entry<String, Integer>> urls_heap = new PriorityQueue<Map.Entry<String, Integer>>(
				20, comparator);
		urls_heap.addAll(urls.getDictionary().entrySet());

		chartCreator.url_chart(urls_heap);
		urls_heap.clear();
		urls_heap = null;
	}

	public void parse_domain_hits(Counter<String> domains) {

		// ORDER DOMAINS
		PriorityQueue<Entry<String, Integer>> domains_heap = new PriorityQueue<Map.Entry<String, Integer>>(
				20, comparator);
		domains_heap.addAll(domains.getDictionary().entrySet());

		chartCreator.domains_chart(domains_heap);
		domains_heap.clear();
		domains_heap = null;
	}

	/**
	 * CCDF
	 * 
	 * @param response_times
	 */
	public void parse_response_times(Counter<Integer> response_times,
			long sample_size) {
		CounterComparatorByKey<Integer> comparator = new CounterComparatorByKey<Integer>();

		PriorityQueue<Entry<Integer, Integer>> response_times_heap = new PriorityQueue<Map.Entry<Integer, Integer>>(
				20, comparator);
		response_times_heap.addAll(response_times.getDictionary().entrySet());

		chartCreator.response_times_chart(response_times_heap, sample_size);
		response_times_heap.clear();
		response_times_heap = null;

	}

	public void parse_response_codes(Counter<Integer> codes,
			HashMap<Integer, Counter<InetAddress>> code_counters) {
		CounterComparator<Integer> comparator = new CounterComparator<Integer>();

		PriorityQueue<Entry<Integer, Integer>> codes_heap = new PriorityQueue<Map.Entry<Integer, Integer>>(
				20, comparator);
		codes_heap.addAll(codes.getDictionary().entrySet());

		// FALTAN COSAS

		HashMap<Integer, PriorityQueue<Entry<InetAddress, Integer>>> code_counters_heaps = new HashMap<Integer, PriorityQueue<Entry<InetAddress, Integer>>>();
		for (Integer k : code_counters.keySet()) {
			PriorityQueue<Entry<InetAddress, Integer>> heap = new PriorityQueue<Entry<InetAddress, Integer>>(
					20, comparatorIP);
			heap.addAll(code_counters.get(k).getDictionary().entrySet());
			code_counters_heaps.put(k, heap);
		}

		chartCreator.response_codes_chart(codes_heap, code_counters_heaps);

		codes_heap.clear();
		codes_heap = null;

	}
}
