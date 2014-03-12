import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.RandomAccessFile;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.sql.Date;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map.Entry;
import java.util.PriorityQueue;
import java.util.SimpleTimeZone;
import java.util.TreeMap;
import java.util.concurrent.Semaphore;

public class FileParser {

	private final DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	private Semaphore semaphore = new Semaphore(1);
	private String filename = null;
	private String path = null;
	private String[] dirs = { "hits", "response_codes", "stats" };
	private int dir_counter = -1;
	private TreeMap<Long, Long> short_index;
	private TreeMap<Long, ArrayList<Tuple<Long, Long>>> long_index;

	// RESPONSE CODES
	private Counter<Integer> codes = null;
	private HashMap<Integer, Counter<InetAddress>> code_counters = null;

	// HITS
	private Counter<InetAddress> ips = null;
	private Counter<String> domains = null;
	private Counter<String> urls = null;

	// RESPONSE_TIMES
	private Counter<Integer> response_times = null;
	private ArrayList<Double> resp_times = null;
	private Double max_response_time = (double) 0;

	private long line_counter = 0;
	private boolean running = true;

	// FLOWPROCESS
	private Counter<Integer> conections_per_sec = null;
	//

	private Runnable thread_task = new Runnable() {

		@Override
		public void run() {
			try {
				while (running) {
					Thread.sleep(main.getQuota() * 60 * 60 * 1000);
					semaphore.acquire();
					parseQuota();

					createDirectories();
					semaphore.release();
				}
			} catch (InterruptedException e) {
				return;
			}
		}
	};

	// FUNCTIONS
	public interface Function {
		int parseLine(String line);
	}

	public Function flowProcess = new Function() {
		public int parseLine(String line) {
			// SPLIT LINE
			String[] split_line = line.split(" ");
			if (split_line.length != 11) {
				return -1;
			}

			int sec = (int) Double.parseDouble(split_line[10]);

			conections_per_sec.update(sec);
			line_counter++;

			return sec;
		}
	};

	public Function httpDissector = new Function() {
		public int parseLine(String line) {
			// SPLIT LINE
			String[] splitted_line = line.split("\\|", 12);

			if (splitted_line.length != 12) {
				return -1;
			}
			String url = null;
			if (main.getNoHostNames()) {
				url = splitted_line[2] + splitted_line[11];
			} else {
				url = splitted_line[10] + splitted_line[11];
			}

			if (main.getChomp_URL()) {
				int pos = url.indexOf('?');
				if (pos != -1) {
					url = url.substring(0, pos);
				}
			}

			if (main.getFilterMode() == 1) {
				// IP
				if (!main.getPattern().matcher(splitted_line[2]).find()) {
					return -2;
				}
			} else if (main.getFilterMode() == 2) {
				// URL
				if (!main.getPattern().matcher(url).find()) {
					return -3;
				}
			} else if (main.getFilterMode() == 3) {
				// DOMAIN
				if (!main.getPattern().matcher(splitted_line[10]).find()) {
					return -4;
				}
			}

			InetAddress ip;
			try {
				ip = InetAddress.getByName(splitted_line[2]);
			} catch (UnknownHostException e) {
				System.err.println("Error en el formato de la ip: "
						+ splitted_line[2]);
				return -5;
			}

			// RESPONSE CODES
			Integer code = Integer.parseInt(splitted_line[8]);
			codes.update(code);
			if (!code_counters.containsKey(code)) {
				code_counters.put(code, new Counter<InetAddress>());
			}
			code_counters.get(code).update(ip);

			// HITS
			ips.update(ip);
			urls.update(url);
			domains.update(splitted_line[10]);

			// RESPONSE_TIMES
			Double r = Double.parseDouble(splitted_line[6]);
			resp_times.add(r);
			response_times.update((int) (r * 1000));
			if (r > max_response_time) {
				max_response_time = r;
			}
			line_counter++;

			return (int) Double.parseDouble(splitted_line[4]);

		}

	};

	// ////////////////////

	public FileParser(String filename) {
		this.filename = filename;

		if (main.isFlowprocess()) {
			conections_per_sec = new Counter<Integer>();
		} else {
			ips = new Counter<InetAddress>();
			domains = new Counter<String>();
			urls = new Counter<String>();
			response_times = new Counter<Integer>();
			resp_times = new ArrayList<Double>();
			codes = new Counter<Integer>();
			code_counters = new HashMap<Integer, Counter<InetAddress>>();
		}

		df.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));

	}

	public FileParser(String filename, String path) {
		this.filename = filename;
		this.path = path;

		if (main.isFlowprocess()) {
			conections_per_sec = new Counter<Integer>();
		} else {
			ips = new Counter<InetAddress>();
			domains = new Counter<String>();
			urls = new Counter<String>();
			response_times = new Counter<Integer>();
			resp_times = new ArrayList<Double>();
			codes = new Counter<Integer>();
			code_counters = new HashMap<Integer, Counter<InetAddress>>();
		}

		df.setTimeZone(new SimpleTimeZone(SimpleTimeZone.UTC_TIME, "UTC"));
	}

	public boolean createDirectories() {
		String path = null;

		if (main.getQuota() > 0) {
			dir_counter += 1;
			path = main.getPath() + dir_counter;
		} else {
			path = main.getPath();
		}

		if (main.isFlowprocess()) {
			if (main.getPath() != null) {
				File dir = new File(path);
				if (!dir.exists()) {
					System.err.println("Creating directory: " + path);
					boolean result = dir.mkdirs();
					if (!result) {
						System.err.println("Couldn't create the directory: "
								+ path);
						return false;
					}
				}
			}
		} else {
			for (String s : dirs) {
				if (main.getPath() != null) {
					s = path + "/" + s;
					File dir = new File(path);
					if (!dir.exists()) {
						System.err.println("Creating directory: " + path);
						boolean result = dir.mkdirs();
						if (!result) {
							System.err
									.println("Couldn't create the directory: "
											+ path);
							return false;
						}
					}
				}
				File dir = new File(s);
				if (!dir.exists()) {
					System.err.println("Creating directory: " + s);
					boolean result = dir.mkdirs();
					if (!result) {
						System.err.println("Couldn't create the directory: "
								+ s);
						return false;
					}
				}
			}
		}
		return true;
	}

	public void loadIndex() {
		if (main.isShortIndex()) {
			loadShortIndex();
		} else {
			loadVerboseIndex();
		}
	}

	private ArrayList<Tuple<Long, Long>> parseIntervalOfBytes(String line) {
		line = line.replace("), (", " ").replaceAll("[\\[\\](),]", "");
		String[] split_line = line.split(" ");
		ArrayList<Tuple<Long, Long>> tuplas = new ArrayList<Tuple<Long, Long>>();
		for (int i = 0; i < split_line.length; i += 2) {
			tuplas.add(new Tuple<Long, Long>(Long.parseLong(split_line[i]),
					Long.parseLong(split_line[i + 1])));

		}

		return tuplas;

	}

	private ArrayList<Tuple<Long, Long>> get_byte_interval(long from, long to) {

		PriorityQueue<Tuple<Long, Long>> tuplas = new PriorityQueue<Tuple<Long, Long>>();
		for (Entry<Long, ArrayList<Tuple<Long, Long>>> e : long_index.subMap(
				from, to).entrySet()) {

			tuplas.addAll(e.getValue());
		}

		ArrayList<Tuple<Long, Long>> byte_interval = new ArrayList<Tuple<Long, Long>>();

		Tuple<Long, Long> last_tuple = tuplas.poll();

		while (!tuplas.isEmpty()) {
			Tuple<Long, Long> t = tuplas.poll();
			if (last_tuple.getY().equals(t.getX())) {
				last_tuple.setY(t.getY());
			} else {
				byte_interval.add(last_tuple);
				last_tuple = t;
			}
		}

		byte_interval.add(last_tuple);

		return byte_interval;

	}

	private void loadVerboseIndex() {
		this.long_index = new TreeMap<Long, ArrayList<Tuple<Long, Long>>>();
		BufferedReader br = null;
		FileReader f = null;
		String line = null;
		try {
			f = new FileReader(main.getIndex());
			br = new BufferedReader(f, 1024 * 1024);

			while ((line = br.readLine()) != null) {
				String[] split_line = line.split(" ", 2);
				long_index.put(Long.parseLong(split_line[0]),
						parseIntervalOfBytes(split_line[1]));
			}
		} catch (FileNotFoundException e) {
			System.err.println("File Not Found\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private void loadShortIndex() {
		BufferedReader br = null;
		FileReader f = null;
		String line = null;
		try {
			f = new FileReader(main.getIndex());
			br = new BufferedReader(f, 1024 * 1024);
			short_index = new TreeMap<Long, Long>();
			while ((line = br.readLine()) != null) {
				String[] split_line = line.split(" ");
				short_index.put(Long.parseLong(split_line[0]),
						Long.parseLong(split_line[1]));
			}
		} catch (FileNotFoundException e) {
			System.err.println("File Not Found\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	@SuppressWarnings("unchecked")
	public Long getClosestKeyFromIndex(long k, boolean from) {

		TreeMap<Long, Object> index = getIndex();

		boolean key;
		Long firstKey = index.firstKey();
		Long lastKey = index.lastKey();

		if (k < firstKey || k > lastKey) {
			return null;
		}

		key = index.containsKey(k);
		if (key == false) {

			if (from) {
				return index.lowerKey(k);
			} else {
				return index.higherKey(k);
			}

		}

		return k;

	}

	private long parseFileByteRange(long startByte, long endByte, Function f) {

		int bytesToRead = (int) (endByte - startByte);

		byte[] buffer = new byte[512];
		StringBuffer sBuffer = new StringBuffer(2048);
		int nRead = 0;
		long total = 0L;
		RandomAccessFile rfile = null;
		try {
			rfile = new RandomAccessFile(filename, "r");
			rfile.seek(startByte);
			readingLoop: while ((nRead = rfile.read(buffer)) != -1) {
				semaphore.acquire();

				sBuffer.append(new String(buffer));
				String[] lines = sBuffer.toString().split("\n");
				for (int i = 0; i < lines.length - 1; i++) {
					f.parseLine(lines[i]);
				}
				sBuffer = new StringBuffer(lines[lines.length - 1]);
				buffer = new byte[512];
				if (rfile.getFilePointer() >= endByte) {
					break readingLoop;
				}

				semaphore.release();
				total += nRead;
			}

			semaphore.release();

			if (rfile != null)
				rfile.close();

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return total;
	}

	public long parseFileStartingAtByteWithLongIndex(long from, long to) {
		ArrayList<Tuple<Long, Long>> byte_interval = get_byte_interval(from, to);

		long totalBytes = 0;
		Function f = null;
		if (main.isFlowprocess()) {
			f = flowProcess;
		} else {
			f = httpDissector;
		}

		for (Tuple<Long, Long> t : byte_interval) {
			totalBytes += parseFileByteRange(t.getX(), t.getY(), f);
		}

		System.err.println("File has been read.");
		parseQuota();

		return totalBytes;

	}

	@SuppressWarnings("unchecked")
	public Long getFirstKeyFromIndex() {
		TreeMap<Long, Object> index = getIndex();
		return index.firstKey();
	}

	@SuppressWarnings("rawtypes")
	private TreeMap getIndex() {
		if (main.isShortIndex()) {
			return short_index;
		} else {
			return long_index;
		}
	}

	@SuppressWarnings("unchecked")
	private int check_range_to_parse(long from, long to) {

		TreeMap<Long, Object> index = getIndex();
		Long startKey = getClosestKeyFromIndex(from, true);
		Long endKey = getClosestKeyFromIndex(to, false);

		if (startKey == null || endKey == null || startKey == endKey
				|| from == to || from > to) {
			System.err.println("Error in the provided timestamps.");
			System.err.println("\nThe first entry in the index is:\n\t"
					+ index.firstKey() + " => "
					+ df.format(new Date(index.firstKey() * 1000)));
			System.err.println("\nAnd the last one is:\n\t" + index.lastKey()
					+ " => " + df.format(new Date(index.lastKey() * 1000)));
			System.err
					.println("\nPlease, provide a timestamp in a range between this two.");
			return -1;
		}

		return 0;

	}

	public long parseFileStartingAtByte(long from, long to) {

		Function f = null;
		if (main.isFlowprocess()) {
			f = flowProcess;
		} else {
			f = httpDissector;
		}

		if (check_range_to_parse(from, to) == -1) {
			return -1;
		}

		Long startKey = getClosestKeyFromIndex(from, true);
		Long endKey = getClosestKeyFromIndex(to, false);
		Date startDate = new Date(startKey * 1000);
		Date endDate = new Date(endKey * 1000);

		System.err.println("Processing file from " + df.format(startDate)
				+ " to " + df.format(endDate) + " UTC");

		if (!main.isShortIndex()) {
			return parseFileStartingAtByteWithLongIndex(from, to);
		}

		long startByte = short_index.get(startKey);
		long endByte = short_index.get(endKey);

		long total = parseFileByteRange(startByte, endByte, f);

		System.err.println("File has been read.");
		parseQuota();

		return total;
	}

	public void parseFile() {

		Function f = null;
		if (main.isFlowprocess()) {
			f = flowProcess;
		} else {
			f = httpDissector;
		}

		Thread thread = null;
		BufferedReader br = null;
		String line = "";
		try {
			FileReader file = null;

			if (this.filename.equals("-")) {
				br = new BufferedReader(new InputStreamReader(System.in),
						1024 * 1024);
			} else {
				file = new FileReader(this.filename);
				br = new BufferedReader(file, 1024 * 1024);
			}

			if (main.getQuota() > 0) {
				thread = new Thread(thread_task);
				thread.start();
			}

			while ((line = br.readLine()) != null) {
				semaphore.acquire();
				f.parseLine(line);
				semaphore.release();
			}

			if (main.getQuota() > 0) {
				running = false;
				thread.interrupt();
			}

		} catch (FileNotFoundException e) {
			System.err.println("File Not Found\n");
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		System.err.println("The file has been read.");
		parseQuota();

		try {
			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void parseQuota() {

		DataParser parser = null;

		if (main.isFlowprocess()) {
			parser = new DataParser(main.getPath());

			parser.parse_flowprocess_conections(conections_per_sec);

			conections_per_sec.clear();
		} else {

			if (main.getQuota() > 0) {
				parser = new DataParser(main.getPath() + dir_counter);
			} else {
				parser = new DataParser(main.getPath());
			}

			parser.parse_ip_hits(ips);
			parser.parse_url_hits(urls);
			parser.parse_domain_hits(domains);

			parser.parse_response_times(response_times, line_counter);
			parser.parse_response_codes(codes, code_counters);

			ips.clear();
			urls.clear();
			domains.clear();
			codes.clear();
			code_counters.clear();
		}

		parser = null;
		System.gc();
		line_counter = 0;

	}
}
