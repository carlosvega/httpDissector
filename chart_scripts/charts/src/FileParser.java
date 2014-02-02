import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;

public class FileParser {

	private String filename = null;
	private String path = null;
	private String[] dirs = { "hits", "response_codes", "stats" };

	public FileParser(String filename) {
		this.filename = filename;
	}

	public FileParser(String filename, String path) {
		this.filename = filename;
		this.path = path;
	}

	public boolean createDirectories() {
		for (String s : dirs) {
			if (main.getPath() != null) {
				s = main.getPath() + "/" + s;
				File dir = new File(main.getPath());
				if (!dir.exists()) {
					System.err.println("Creating directory: " + main.getPath());
					boolean result = dir.mkdirs();
					if (!result) {
						System.err.println("Couldn't create the directory: "
								+ main.getPath());
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

	public void parseFile() {
		// RESPONSE CODES
		Counter<Integer> codes = new Counter<Integer>();
		HashMap<Integer, Counter<InetAddress>> code_counters = new HashMap<Integer, Counter<InetAddress>>();

		// HITS
		Counter<InetAddress> ips = new Counter<InetAddress>();
		Counter<String> domains = new Counter<String>();
		Counter<String> urls = new Counter<String>();

		// RESPONSE_TIMES
		Counter<Integer> response_times = new Counter<Integer>();
		ArrayList<Double> resp_times = new ArrayList<Double>();
		Double max_response_time = (double) 0;

		long line_counter = 0;

		// System.out.println(ips.getDictionary());

		BufferedReader br = null;
		try {
			FileReader f = new FileReader(this.filename);
			br = new BufferedReader(f, 512 * 1024);
			String line = "";

			while ((line = br.readLine()) != null) {

				// SPLIT LINE
				String[] splitted_line = line.split("\\|", 12);
				String url = splitted_line[10] + splitted_line[11];

				if (main.getFilterMode() == 1) {
					// IP
					if (!main.getPattern().matcher(splitted_line[2]).find()) {
						continue;
					}
				} else if (main.getFilterMode() == 2) {
					// URL
					if (!main.getPattern().matcher(url).find()) {
						continue;
					}
				} else if (main.getFilterMode() == 3) {
					// DOMAIN
					if (!main.getPattern().matcher(splitted_line[10]).find()) {
						continue;
					}
				}

				line_counter++;
				InetAddress ip = InetAddress.getByName(splitted_line[2]);

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

			}

		} catch (FileNotFoundException e) {
			System.err.println("File Not Found\n");
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Fichero Leido");
		DataParser parser = new DataParser();
		parser.parse_ip_hits(ips);
		parser.parse_url_hits(urls);
		parser.parse_domain_hits(domains);
		ips = null;
		urls = null;
		domains = null;
		System.gc();

		parser.parse_response_times(response_times, line_counter);
		parser.parse_response_codes(codes, code_counters);

		try {
			br.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
