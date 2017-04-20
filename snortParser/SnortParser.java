import java.util.regex.*;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * <h1>The Snort Rule Header</h1> The Header object represents all header
 * contents in a snort rule
 * <p>
 * <b>Note:</b> Initialized with a header string from a rule. Unmashall to a
 * Header object
 *
 * @author York Chen
 * @version 1.0
 * @since 2017-04-20
 */
class Header {

	private String action = null;
	private String protocol = null;
	private String sourceIp = null;
	private String sourcePort = null;
	private String direction = null;
	private String destinationIp = null;
	private String destinationPort = null;
	private String header = null;

	public Header(String header) {
		this.header = header;
		setHeader(header);
	}

	public String getAction() {
		return action;
	}

	public String getProtocol() {
		return protocol;
	}

	public String getSourceIp() {
		return sourceIp;
	}

	public String getSourcePort() {
		return sourcePort;
	}

	public String getDirection() {
		return direction;
	}

	public String getDestinationIp() {
		return destinationIp;
	}

	public String getDestinationPort() {
		return destinationPort;
	}

	public String getHeader() {
		if (header != null && header.length() > 5)
			return header;

		if (this.action == null || this.protocol == null || this.sourceIp == null || this.sourcePort == null
				|| this.direction == null || this.destinationIp == null || this.destinationPort == null)
			return null;

		return this.action + " " + this.protocol + " " + this.sourceIp + " " + this.sourcePort + " " + this.direction
				+ " " + this.destinationIp + " " + this.destinationPort;

	}

	public void setAction(String action) {
		this.action = action;
	}

	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	public void setSourceIp(String sourceIp) {
		this.sourceIp = sourceIp;
	}

	public void setSourcePort(String sourcePort) {
		this.sourcePort = sourcePort;
	}

	public void setDirection(String direction) {
		this.direction = direction;
	}

	public void setDestinationIp(String destinationIp) {
		this.destinationIp = destinationIp;
	}

	public void setDestinationPort(String destinationPort) {
		this.destinationPort = destinationPort;
	}

	public void setHeader(String header) {
		if (header == null)
			return;

		header = header.replace("  ", " ");

		this.header = header;

		String[] headers = this.header.split("\\s");
		if (headers.length > 6) {
			this.action = headers[0];
			this.protocol = headers[1];
			this.sourceIp = headers[2];
			this.sourcePort = headers[3];
			this.direction = headers[4];
			this.destinationIp = headers[5];
			this.destinationPort = headers[6];
		} else {
			this.action = null;
			this.protocol = null;
			this.sourceIp = null;
			this.sourcePort = null;
			this.direction = null;
			this.destinationIp = null;
			this.destinationPort = null;
		}

	}

	public boolean hasValue() {
		if (header == null)
			return false;
		else
			return true;
	}

}

/**
 * <h1>The Option Object</h1> The Option object in Snort. One rule contains
 * multi-options. Each option may or may not have value. But it must have name
 * <p>
 * <b>Note:</b> Initialized with an option string from a rule. Unmashall to
 * Option object
 *
 * @author York Chen
 * @version 1.0
 * @since 2017-04-20
 */
class Option {

	private String name;
	private String value = null;

	public Option(String name) {
		this.name = name;
	}

	public Option(String name, String value) {
		this.name = name;
		this.value = value;
	}

	public String getName() {
		return name;
	}

	public String getValue() {
		String ret = value;
		if (ret == null)
			return ret;
		if (ret.startsWith("\"") && ret.endsWith("\""))
			ret = ret.substring(1, ret.length() - 1);
		return ret;
	}

	public boolean hasValue() {
		if (value == null)
			return false;
		else
			return true;
	}
}

/**
 * <h1>The Option Object</h1>
 * <p>
 * This class provides the ability to parse Snort rules and evaluate content to
 * determine if the Snort rules match.
 * <p>
 * <b>Note:</b> Parser a rule into 2 objects first. Header object and Options
 * object Options can be parsed into iCode intermediate data file and the rule
 * image file iCode intermediate data file only includes content option and PCRE
 * option Rule Image file includes all other options except content and PCRE
 *
 * @author York Chen
 * @version 1.0
 * @since 2017-04-20
 */
public class SnortParser {

	private String SnortParserName;
	private int sid;
	private int revision;
	private String classtype;

	private Vector<Option> options = new Vector<Option>();
	private Vector<Reference> references = new Vector<Reference>();
	private Header header = null;
	private static final Pattern SNORT_RULE_REGEX = Pattern.compile(
			"([a-zA-Z]+) ([a-zA-Z]+) ([0-9a-zA-Z$_]+) ([0-9a-zA-Z$_]+) (\\->|<>|<\\-) ([0-9a-zA-Z$_]+) ([0-9a-zA-Z$_]+) (\\()([ /()a-zA-Z%0-9=!?._;:,\\-$\\\"\\']*)(\\))");
	private static final Pattern SNORT_OPTIONS_REGEX = Pattern.compile(
			"([ ]*([()a-zA-Z0-9._,\\-$']+)(:[ ]*(([ /()a-zA-Z%0-9=!?._,\\-$']+)|\"([ /()a-zA-Z%0-9!?=._,\\-$']+)\"))?)+");

	/**
	 * <h1>The Reference Object</h1>
	 * <p>
	 * This class represents a Snort signature reference (URL, CVE entry, etc.).
	 * <p>
	 * <b>Note:</b>
	 *
	 * @author York Chen
	 * @version 1.0
	 * @since 2017-04-20
	 */
	public static class Reference {

		public final static Type BUGTRAQ = new Type(1, "http://www.securityfocus.com/bid/");
		public final static Type CVE = new Type(2, "http://cve.mitre.org/cgi-bin/cvename.cgi?name=");
		public final static Type NESSUS = new Type(3, "http://cgi.nessus.org/plugins/dump.php3?id=");
		public final static Type ARACHNIDS = new Type(4, "http://www.whitehats.com/info/IDS");
		public final static Type MCAFEE = new Type(5, "http://vil.nai.com/vil/dispVirus.asp?virus_k=");
		public final static Type URL = new Type(6, "http://");

		/**
		 * This class represents the possible Snort reference types. See
		 * http://www.snort.org/docs/snort_htmanuals/htmanual_2.4/node18.html#SECTION00442000000000000000
		 * 
		 * @author York Chen
		 *
		 */
		public static class Type {

			private int id;
			private String urlPrefix;

			protected Type(int id, String urlPrefix) {
				this.id = id;
				this.urlPrefix = urlPrefix;
			}

			public String getUrlPrefix() {
				return urlPrefix;
			}

			public boolean equals(Type type) {

				// 0 -- Precondition check
				if (type == null) {
					throw new IllegalArgumentException("Type cannot be null");
				}

				// 1 -- Compare the types
				return type.id == id;
			}
		}

		private Type type;
		private String value;

		public Reference(Type type, String value) {
			this.type = type;
			this.value = value;
		}

		/**
		 * Parser the reference option.
		 * 
		 * @param value
		 * @return Reference
		 * @throws SnortParseException
		 */
		public static Reference parse(String value) throws SnortParseException {
			int firstComma = value.indexOf(',');

			String type = value.substring(0, firstComma).trim();
			String argument = value.substring(firstComma + 1).trim();

			if (type.equalsIgnoreCase("bugtraq")) {
				return new Reference(Reference.BUGTRAQ, argument);
			} else if (type.equalsIgnoreCase("cve")) {
				return new Reference(Reference.CVE, argument);
			} else if (type.equalsIgnoreCase("nessus")) {
				return new Reference(Reference.NESSUS, argument);
			} else if (type.equalsIgnoreCase("arachnids")) {
				return new Reference(Reference.ARACHNIDS, argument);
			} else if (type.equalsIgnoreCase("mcafee")) {
				return new Reference(Reference.MCAFEE, argument);
			} else if (type.equalsIgnoreCase("url")) {
				return new Reference(Reference.URL, argument);
			} else {
				throw new SnortParseException("Reference name (\"" + type + "\" is invalid");
			}
		}

		public String toString() {
			return type.getUrlPrefix() + value;
		}
	}

	/**
	 * Parser the header of a rule to HaspMap.
	 * 
	 * @param snortRule
	 * @return HashMap<String, Object>
	 * @throws SnortParseException
	 */
	public static HashMap<String, Object> parseHeaderOptions(String snortRule) {
		HashMap<String, Object> rule = new HashMap<String, Object>();

		try {
			String[] list = snortRule.split("\\(");
			String header = list[0];
			Header h = new Header(header);

			String options = snortRule.substring(header.length() + 1, snortRule.length());
			options = options.trim();
			if (options.endsWith(";)"))
				options = options.substring(0, options.length() - 2);

			rule.put("header", h);
			rule.put("options", options);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

		return rule;

	}

	/**
	 * Takes a Snort rule file and creates an list of SnortParser object that is
	 * capable of evaluating content for exploits.
	 * 
	 * @param snortRuleFile
	 * @return ArrayList<SnortParser>
	 * @throws SnortParseException
	 */
	public static ArrayList<SnortParser> parseFile(String snortRuleFile) throws SnortParseException {
		ArrayList<SnortParser> ret = new ArrayList<SnortParser>();
		FileInputStream fis = null;

		try {
			Path path = Paths.get(snortRuleFile);

			if (!Files.exists(path))
				return null;

			fis = new FileInputStream(snortRuleFile);

		} catch (Exception e) {
			e.printStackTrace();
			return null;
		}

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(fis))) {
			String line = null;
			while ((line = reader.readLine()) != null) {
				if (!line.trim().startsWith("#") && line.length() > 5) {
					SnortParser snortSig = parse(line);
					if (snortSig != null && snortSig.getHeader() != null) {
						ret.add(snortSig);
					}
				}
			}
			fis.close();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return ret;
	}

	/**
	 * Takes a Snort rule string and creates an SnortParser object that is
	 * capable of evaluating content for exploits.
	 * 
	 * @param snortRule
	 * @return
	 * @throws SnortParseException
	 */
	public static SnortParser parse(String snortRule) throws SnortParseException {

		// 1 -- Precondition check

		// 1.1 --Rule must not be null
		if (snortRule == null) {
			throw new IllegalArgumentException("Snort rule must not be null");
		}

		// 1.2 --Rule must not be empty
		if (snortRule.isEmpty()) {
			throw new IllegalArgumentException("Snort rule must not be empty");
		}

		// 2 -- Parse out the rule options
		SnortParser snortSig = new SnortParser();

		HashMap<String, Object> rule = snortSig.parseHeaderOptions(snortRule);

		Header header = (Header) rule.get("header");

		// 3. -- Set Rule Header info
		snortSig.setHeader(header);

		// 4. -- Get all options from rule
		String options = (String) rule.get("options");

		// 5. -- Set Rule Options info
		String[] vOptions = options.split(";");
		for (String sOption : vOptions) {
			String[] optionPair = sOption.split(":");

			// 5.1 -- Save the option to the list
			String optionName = optionPair[0].trim();

			String optionValue = null;

			if (optionPair.length > 1) {
				optionValue = optionPair[1];
			}

			// 5.2 -- Save the option to the list
			if (optionValue == null) {
				snortSig.options.add(new Option(optionName));
			} else {
				snortSig.options.add(new Option(optionName, optionValue));
			}

		}

		// 6 -- Populate the signature from the options
		for (int c = 0; c < snortSig.options.size(); c++) {
			Option option = snortSig.options.get(c);

			if (option.getName().equalsIgnoreCase("msg")) {
				snortSig.SnortParserName = option.getValue();
			}

			if (option.getName().equalsIgnoreCase("sid")) {
				snortSig.sid = Integer.parseInt(option.getValue());
			}

			if (option.getName().equalsIgnoreCase("rev")) {
				snortSig.revision = Integer.parseInt(option.getValue());
			}

			if (option.getName().equalsIgnoreCase("classtype")) {
				snortSig.classtype = option.getValue();
			}

			if (option.getName().equalsIgnoreCase("reference")) {
				snortSig.references.add(Reference.parse(option.getValue()));
			}
		}

		return snortSig;
	}

	public String getName() {
		String description = "This signature detects attacks originating from monitored resource. Details are below:\n\nSignature: "
				+ SnortParserName;

		if (references != null && references.size() > 0) {
			return description + "\nReferences:\n" + getNotes();
		} else
			return description;
	}

	public String getNotes() {
		StringBuffer notes = new StringBuffer("");
		if (references != null) {
			for (int c = 0; c < references.size(); c++) {
				if (c > 0) {
					notes.append("\n" + references.get(c).toString());
				} else {
					notes.append(references.get(c).toString());
				}
			}
		}

		return notes.toString();
	}

	public String getCategoryName() {
		return "Exploit Signature";
	}

	public String getClassType() {
		return classtype;
	}

	public Reference[] getReferences() {
		return (Reference[]) references.toArray();
	}

	public String getSubCategoryName() {
		return SnortParserName;
	}

	public int getID() {
		return sid;
	}

	public int getRevision() {
		return revision;
	}

	public Option[] getOptions() {
		Option[] optionsArray = new Option[options.size()];
		options.toArray(optionsArray);

		return optionsArray;
	}

	public Header getHeader() {
		return this.header;
	}

	public void setHeader(Header header) {
		this.header = header;
	}

	/**
	 * Pickup all the options from a rule except content option and PCRE option.
	 * 
	 * @param
	 * @return ArrayList<Option>
	 * @throws SnortParseException
	 */
	public ArrayList<Option> getOtherOptions() {
		Option[] ops = getOptions();

		ArrayList<Option> ret = new ArrayList<Option>();

		for (Option o : ops) {
			String name = o.getName();

			if (!name.equalsIgnoreCase("content") && !name.equalsIgnoreCase("pcre")) {
				ret.add(o);
			}
		}

		return ret;
	}

	/**
	 * Pickup all the options from a rule except content option and PCRE option.
	 * 
	 * @param
	 * @return String
	 * @throws SnortParseException
	 */
	public String getPlainOtherOptions() {
		Option[] ops = getOptions();

		String ret = "";

		for (Option o : ops) {
			String name = o.getName().trim();

			String value = o.getValue();
			String pair = "";

			if (value == null || value.isEmpty())
				pair = name;
			else
				pair = name + ":" + value;

			if (!name.equalsIgnoreCase("content") && !name.equalsIgnoreCase("pcre")) {
				if (ret.isEmpty()) {
					ret = pair;

				} else {
					ret = ret + "; " + pair;
				}
			}
		}

		return ret;
	}

	/**
	 * Pickup all content options PCRE options from a rule.
	 * 
	 * @param
	 * @return ArrayList<String>
	 * @throws SnortParseException
	 */
	public ArrayList<String> getiCode() {
		Option[] ops = getOptions();

		ArrayList<String> ret = new ArrayList<String>();

		for (Option o : ops) {
			if (o.getName().equalsIgnoreCase("content") || o.getName().equalsIgnoreCase("pcre")) {
				String value = o.getValue();

				if (!value.isEmpty())
					ret.add(o.getValue());
			}
		}

		return ret;
	}

	/**
	 * SnortParser.java test cases.
	 * 
	 * @param @return void @throws
	 */
	// public static void main(String[] args) {
	// String file = "/home/odl/workspace/StandaloneTest/rules/icmp.rules";
	// String snortRule = "alert icmp $HOME_NET any -> $EXTERNAL_NET any
	// (msg:\"GPL ICMP Time-To-Live Exceeded in Transit undefined code\";
	// icode:>1; itype:11; classtype:misc-activity; sid:2100450; rev:9)";
	// snortRule = "alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:\"ICMP
	// digital island bandwidth query\"; content:\"mailto|3A|ops@digisle.com\";
	// depth:22; classtype:misc-activity; sid:1813; rev:5;)";
	// SnortParser a = new SnortParser();
	// String iCode = "";
	// ArrayList<String> icodes = new ArrayList<String>();
	//
	// try {
	// ArrayList<SnortParser> v = SnortParser.parseFile(file);
	// for (SnortParser b : v) {
	// Option[] opts = b.getOptions();
	// icodes.addAll(b.getiCode());
	// System.out.println(b.getHeader().getHeader());
	// }
	//
	// for (String s : icodes) {
	// System.out.println(s);
	// }
	// } catch (Exception e) {
	// e.printStackTrace();
	// }
	//
	// }

}
