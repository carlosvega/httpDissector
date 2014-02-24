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
import java.util.TreeMap;
import java.util.concurrent.Semaphore;

public class FileParser {

	private final DateFormat df = new SimpleDateFormat("dd/MM/yyyy HH:mm:ss");
	private Semaphore semaphore = new Semaphore(1);
	private String filename = null;
	private String path = null;
	private String[] dirs = { "hits", "response_codes", "stats" };
	private int dir_counter = -1;
	private TreeMap<Long, Long> index;

	// RESPONSE CODES
	private Counter<Integer> codes = new Counter<Integer>();
	private HashMap<Integer, Counter<InetAddress>> code_counters = new HashMap<Integer, Counter<InetAddress>>();

	// HITS
	private Counter<InetAddress> ips = new Counter<InetAddress>();
	private Counter<String> domains = new Counter<String>();
	private Counter<String> urls = new Counter<String>();

	// RESPONSE_TIMES
	private Counter<Integer> response_times = new Counter<Integer>();
	private ArrayList<Double> resp_times = new ArrayList<Double>();
	private Double max_response_time = (double) 0;

	private long line_counter = 0;
	private boolean running = true;

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

	public FileParser(String filename) {

		this.filename = filename;
	}

	public FileParser(String filename, String path) {
		this.filename = filename;
		this.path = path;
	}

	public boolean createDirectories() {
		String path = null;

		if (main.getQuota() > 0) {
			dir_counter += 1;
			path = main.getPath() + dir_counter;
		} else {
			path = main.getPath();
		}

		for (String s : dirs) {
			if (main.getPath() != null) {
				s = path + "/" + s;
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
			File dir = new File(s);
			if (!dir.exists()) {
				System.err.println("Creating directory: " + s);
				boolean result = dir.mkdirs();
				if (!result) {
					System.err.println("Couldn't create the directory: " + s);
					return false;
				}
			}
		}

		return true;
	}

	public TreeMap<Long, Long> getIndex() {
		return index;
	}

	public void loadIndex() {
		BufferedReader br = null;
		FileReader f = null;
		String line = null;
		try {
			f = new FileReader(main.getIndex());
			br = new BufferedReader(f, 1024 * 1024);
			index = new TreeMap<Long, Long>();
			while ((line = br.readLine()) != null) {
				String[] split_line = line.split(" ");
				index.put(Long.parseLong(split_line[0]),
						Long.parseLong(split_line[1]));
			}
		} catch (FileNotFoundException e) {
			System.err.println("File Not Found\n");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	public Long getClosestKeyFromIndex(long k, boolean from) {

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

	public long parseFileStartingAtByte(long start, long end) {
		loadIndex();
		Long startKey = getClosestKeyFromIndex(start, true);
		Long endKey = null;
		if (end > 0) {
			endKey = getClosestKeyFromIndex(end, false);
		}

		if (end == -1L) {
			if (startKey == null) {
				System.err.println("Error in the provided timestamps.");
				System.err.println("\nThe first entry in the index is:\n\t"
						+ index.firstKey() + " => "
						+ df.format(new Date(index.firstKey() * 1000)));
				System.err.println("\nAnd the last one is:\n\t"
						+ index.lastKey() + " => "
						+ df.format(new Date(index.lastKey() * 1000)));
				System.err
						.println("\nPlease, provide a timestamp in a range between this two.");
				return -1;
			}
		} else if (startKey == null || endKey == null || startKey == endKey
				|| start == end) {
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

		Long startByte = index.get(startKey);

		Date startDate = new Date(startKey * 1000);
		Date endDate = null;
		if (end != -1L) {
			endDate = new Date(endKey * 1000);
			System.err.println("Processing file from " + df.format(startDate)
					+ " to " + df.format(endDate));
		}

		byte[] buffer = new byte[512];
		int nRead = 0;
		long total = 0L;
		StringBuffer sBuffer = new StringBuffer(2048);
		String line = null;
		RandomAccessFile rfile = null;
		int lastTimestamp = 0;
		try {
			rfile = new RandomAccessFile(filename, "r");
			rfile.seek(startByte);

			readingLoop: while ((nRead = rfile.read(buffer)) != -1) {
				semaphore.acquire();
				sBuffer.append(new String(buffer));
				String[] lines = sBuffer.toString().split("\n");
				for (int i = 0; i < lines.length - 1; i++) {
					line = lines[i];
					lastTimestamp = parseLine(line);
					if (endKey != null && lastTimestamp >= endKey) {
						break readingLoop;
					}
				}
				sBuffer = new StringBuffer(lines[lines.length - 1]);
				buffer = new byte[512];
				total += nRead;

				semaphore.release();
			}

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

		System.err.println("File has been read.");
		parseQuota();

		return total;
	}

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

	public void parseFile() {

		// System.out.println(ips.getDictionary());

		Thread thread = null;
		BufferedReader br = null;
		String line = "";
		try {
			FileReader f = null;

			if (this.filename.equals("-")) {
				br = new BufferedReader(new InputStreamReader(System.in),
						1024 * 1024);
			} else {
				f = new FileReader(this.filename);
				br = new BufferedReader(f, 1024 * 1024);
			}

			if (main.getQuota() > 0) {
				thread = new Thread(thread_task);
				thread.start();
			}

			while ((line = br.readLine()) != null) {
				semaphore.acquire();
				parseLine(line);
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

		line_counter = 0;
		ips.clear();
		urls.clear();
		domains.clear();
		codes.clear();
		code_counters.clear();
		parser = null;
		System.gc();

	}
}
