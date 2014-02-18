import java.io.FileNotFoundException;
import java.util.regex.Pattern;

import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

public class main {

	String[] caca = new String[] { "ip", "url", "domain" };

	@Option(name = "-i", usage = "Input File. Type '-i -' for reading from sdtin.", required = true, aliases = "--input")
	private static String filename;

	@Option(name = "-q", usage = "Quota. Hours. Create a folder full of charts every <quota> hours.", aliases = "--quota")
	private static int quota = 0;

	@Option(name = "-r", usage = "DPI resolution. Default 1000.", aliases = "--dpi")
	private static int dpi = 1000;

	@Option(name = "-d", usage = "Directory where output will be save", aliases = "--directory")
	private static String path = null;

	@Option(name = "-t", usage = "Chart bars top.", aliases = "--top")
	private static int top = 10;

	@Option(name = "-fm", usage = "Filter Mode: {ip, url, domain}", aliases = "--filter-mode")
	private static String filter_mode = null;
	private static int filter_mode_int = 0;

	@Option(name = "-f", usage = "Filter.", aliases = "--filter")
	private static String filter = null;

	private static Pattern pattern = null;

	public static Pattern getPattern() {
		return pattern;
	}

	public static int getQuota() {
		return quota;
	}

	public static String getPath() {
		return path;
	}

	public static int getTop() {
		return top;
	}

	public static String getFilter() {
		return filter;
	}

	public static int getFilterMode() {
		return filter_mode_int;
	}

	/**
	 * @param args
	 * @throws FileNotFoundException
	 */
	public static void main(String[] args) {

		CmdLineParser parser = new CmdLineParser(new main());

		parser.setUsageWidth(80);

		try {
			parser.parseArgument(args);
		} catch (CmdLineException e) {
			System.err.println(e.getMessage());
			System.err.println("java -jar chart_scripts.jar arguments...");
			parser.printUsage(System.err);
			System.err.println();
			return;
		}

		if (getQuota() > 0) {
			path = filename + "_folder";
		}

		if (filter_mode != null || filter != null) {
			if (filter == null) {
				System.err
						.println("Introduce the filter with the option: --filter");
			}
			if (filter_mode == null) {
				System.err
						.println("Introduce the filter mode with the option: --filter-mode");
			}
		}

		if (filter_mode != null && filter != null) {
			pattern = Pattern.compile(filter);
			if (filter_mode.equals("ip")) {
				filter_mode_int = 1;
			} else if (filter_mode.equals("url")) {
				filter_mode_int = 2;
			} else if (filter_mode.equals("domain")) {
				filter_mode_int = 3;
			} else {
				System.err
						.println("Invalid filter mode. Must be one of {ip, url, domain}");
				return;
			}
		}

		if (!filename.equals("-")) {
			System.out.println(filename);
		} else {
			System.out.println("Reading from STDIN");
		}

		FileParser fileParser = new FileParser(filename);
		fileParser.createDirectories();
		fileParser.parseFile();

	}
}
