import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.nio.file.Files;
import java.util.*;

enum OUTPUT_PATTERN {
	HEADONLY, // only print "<SET>"
	ENDONLY, // only print "</SET>"
	NONE, // Nothing
	BOTH // PRINT both "<SET>" and "</SET>"
}

/**
 * <h1>The SnortFileParserr</h1> This class represents snort rule contents in a
 * snort rule file or folder
 * <p>
 * <b>Note:</b> Initialized with a rule file name.
 *
 * @author York Chen
 * @version 1.0
 * @since 2017-04-20
 */
public class SnortFileParser {

	private String filename = null;
	private ArrayList<Option> options = new ArrayList<Option>();
	private ArrayList<String> icode = new ArrayList<String>();
	private ArrayList<Option> otherOptions = new ArrayList<Option>();
	private ArrayList<String> otherPlainTextOpts = new ArrayList<String>();
	private Header header = null;

	/**
	 * SnortRuleFile Parser the header of a rule to HaspMap.
	 * 
	 * @param snortRule
	 * @return HashMap<String, Object>
	 * @throws SnortParseException
	 */
	public SnortFileParser(String filename) {
		this.filename = filename;

		try {
			ArrayList<SnortParser> v = SnortParser.parseFile(filename);

			if (v != null && v.size() > 0) {
				for (SnortParser b : v) {

					Option[] options_ = b.getOptions();
					ArrayList<Option> otherOptions_ = b.getOtherOptions();
					ArrayList<String> iCode_ = b.getiCode();
					String otherPlainTextOpts_ = b.getPlainOtherOptions();

					if (iCode_.size() > 0)
						icode.addAll(iCode_);

					if (otherOptions_.size() > 0)
						otherOptions.addAll(otherOptions_);

					for (Option o : options_) {
						options.add(o);
					}

					if (!otherPlainTextOpts_.isEmpty())
						otherPlainTextOpts.add(otherPlainTextOpts_);

				}
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public String getFilename() {
		return filename;
	}

	public ArrayList<Option> getOptions() {
		return options;
	}

	public ArrayList<String> getIcode() {
		return icode;
	}

	public ArrayList<Option> getOtherOptions() {
		return otherOptions;
	}

	/**
	 * This method is used to generate iCode (content option and PCRE option)
	 * text.
	 * 
	 * @param
	 * @return String This is the iCode plain text
	 * @throws SnortParseException
	 */
	public String getPlainIcode() {
		ArrayList<String> icodes_ = getIcode();
		String ret = "";
		if (icodes_ == null)
			return "";

		for (String code : icodes_) {
			if (ret.isEmpty())
				ret = code;
			else
				ret = ret + "\n" + code;
		}
		return ret;
	}

	/**
	 * This method is used to generate the other option except content option
	 * and PCRE option
	 * 
	 * @param
	 * @return String This is the other option
	 * @throws SnortParseException
	 */
	public String getPlainOtherOptons() {

		String ret = "";
		if (otherPlainTextOpts.size() < 1)
			return "";

		for (String option : otherPlainTextOpts) {
			if (ret.isEmpty())
				ret = option;
			else
				ret = ret + "\n" + option;
		}
		return ret;
	}

	public Header getHeader() {
		return header;
	}

	/**
	 * This method is used to generate the LIONIC the ruleImage file
	 * 
	 * @param String
	 *            ruleImagefile This is the rule image file name
	 * @param int
	 *            num This is the SET NUMBER in the ruleImage file
	 * @param OUTPUT_PATTERN
	 *            pattern This is the out put patter. Used to decide in a SET or
	 *            a separate SET
	 * @return int This is the next SET NUMBER
	 * @throws SnortParseException
	 */
	public int exportOtherOptions(String ruleImagefile, int num, OUTPUT_PATTERN pattern) {
		BufferedWriter bw = null;
		FileWriter fw = null;
		int ret = num;

		try {
			
			File file = new File(ruleImagefile);
			if (!file.exists()) {
				file.createNewFile();
			}
			
			String sPlainOtherOptions = getPlainOtherOptons();
			fw = new FileWriter(file.getAbsolutePath(), true);
			bw = new BufferedWriter(fw);

			if (sPlainOtherOptions == null || sPlainOtherOptions.isEmpty())
				return num;

			if (pattern == OUTPUT_PATTERN.HEADONLY || pattern == OUTPUT_PATTERN.BOTH)
				bw.write("<SET NUM=" + String.valueOf(num) + ">\n");

			if (sPlainOtherOptions != null && !sPlainOtherOptions.isEmpty())
				bw.write(getPlainOtherOptons() + "\n");

			if (pattern == OUTPUT_PATTERN.ENDONLY || pattern == OUTPUT_PATTERN.BOTH)
				bw.write("</SET>\n");

			ret++;

		} catch (Exception e) {
			e.printStackTrace();

		} finally {
			try {
				if (bw != null)
					bw.close();

				if (fw != null)
					fw.close();

			} catch (Exception e) {
				e.printStackTrace();
			}
		}
		return ret;
	}

	/**
	 * This method is used to generate the LIONIC iCode intermediate data file
	 * 
	 * @param String
	 *            iCodeFile This is the iCode file name
	 * @param int
	 *            num This is the SET NUMBER in the iCode file
	 * @param OUTPUT_PATTERN
	 *            pattern This is the out put patter. Used to decide in a SET or
	 *            a separate SET
	 * @return int This is the next SET NUMBER
	 * @throws SnortParseException
	 */
	public int exportIcode(String iCodefile, int num, OUTPUT_PATTERN pattern) {
		BufferedWriter bw = null;
		FileWriter fw = null;
		int ret = num;

		try {
			File file = new File(iCodefile);
			if (!file.exists()) {
				file.createNewFile();
			}

			fw = new FileWriter(file.getAbsolutePath(), true);
			bw = new BufferedWriter(fw);
			String plainIcode = getPlainIcode();

			if (pattern == OUTPUT_PATTERN.HEADONLY || pattern == OUTPUT_PATTERN.BOTH)
				bw.write("<SET NUM=" + String.valueOf(num) + ">\n");

			if (plainIcode != null & !plainIcode.isEmpty())
				bw.write(getPlainIcode() + "\n");

			if (pattern == OUTPUT_PATTERN.ENDONLY || pattern == OUTPUT_PATTERN.BOTH)
				bw.write("</SET>\n");

			ret++;

		} catch (Exception e) {
			e.printStackTrace();
			ret = 0;

		} finally {
			try {
				if (bw != null)
					bw.close();

				if (fw != null)
					fw.close();

			} catch (Exception e) {
				e.printStackTrace();
				ret = 0;
			}
		}
		return ret;
	}

	/**
	 * This method is used to list all rule files in a folder
	 * 
	 * @param String
	 *            directoryName This folder name with full path
	 * @return File[] This is File Array in the folder
	 * @throws FileIOException
	 */
	private static File[] getSnortRuleFiles(String directoryName) {
		File directory = new File(directoryName);
		File[] rules = directory.listFiles((dir, name) -> {
			return name.toLowerCase().endsWith(".rules");
		});
		return rules;
	}

	/**
	 * This method is used to remove iCode file and ruleImage file
	 * 
	 * @param String
	 *            filepath This file name with full path
	 * @return boolean TRUE if removed succesfully;otherwise FALSE
	 * @throws FileIOException
	 */
	private static boolean removeFile(String filepath) {
		boolean ret = false;
		String msg = "";
		try {
			File file = new File(filepath);
			if (file.delete())
				ret = true;
		} catch (Exception e) {
			msg = e.getMessage();
		}
		return ret;
	}

	/**
	 * This method is used to replace ~/ with home path
	 * 
	 * @param String
	 *            filepath This file name with full path
	 * @return full path
	 * @throws FileIOException
	 */
	private static String implementFullPath(String path) {	
		String home=System.getProperty("user.home");
		String ret=path;
		if (ret.startsWith("~"))
			ret= home + File.separator + ret.substring(2, ret.length());
		
		return ret;
	}

	
	/**
	 * The method that for creating LIONIC iCode intermediate data file and rule
	 * image file (The other opthions)
	 * 
	 * @param snortRule
	 * @return String String String
	 * @throws SnortParseException
	 */
	public static void createLionicTemplateFiles(String path, String iCodeText, String ruleImagefile) {

		int numIcode = 4;
		int numImages = 5;
		String iCode = "";

		removeFile(iCodeText);
		removeFile(ruleImagefile);

		int idx = 0;
		File[] files = SnortFileParser.getSnortRuleFiles(path);
		for (File f : files) {
			String file = f.getAbsolutePath();

			System.out.println("Parsing \"" + file + "\" ......");
			SnortFileParser a = new SnortFileParser(file);

			try {
				if (files.length <= 1) {
					a.exportIcode(iCodeText, numIcode, OUTPUT_PATTERN.BOTH);

				} else {
					if (idx == 0)
						a.exportIcode(iCodeText, numIcode, OUTPUT_PATTERN.HEADONLY);

					else if (idx == files.length - 1)
						a.exportIcode(iCodeText, numIcode, OUTPUT_PATTERN.ENDONLY);

					else
						a.exportIcode(iCodeText, numIcode, OUTPUT_PATTERN.NONE);
				}

				numImages = a.exportOtherOptions(ruleImagefile, numImages, OUTPUT_PATTERN.BOTH);

			} catch (Exception e) {
				e.printStackTrace();
			}
			idx++;
		}
	}

	public static void main(String[] args) {
		// String path = "/home/odl/workspace/StandaloneTest/rules";
		// String iCodeText = "/home/odl/workspace/StandaloneTest/iCode.txt";
		// String ruleImagefile =
		// "/home/odl/workspace/StandaloneTest/ruleImage.txt";
		String path = "/etc/snort/rules";
		String iCodeText = "~/lionic-icode.txt";
		String ruleImagefile = "~/lionic-rule-images.txt";		
		
		List<String> lists = Arrays.asList(args);
		
		if (lists.contains("-h") || lists.contains("--help") 
				|| args.length > 3 || lists.contains("?")) {
			
			System.out.println("Useage:");
			System.out.println("  java -jar SnortFileParser.jar [<ruls-folder> <icodicode-filee-file> <ruleImage-file>]");
			System.out.println("default: ");
			System.out.println("  ruls-folder=/etc/snort/rules");
			System.out.println("  icode-file=~/lionic-icode.txt");
			System.out.println("  ruleImage-file=~/lionic-rule-images.txt");
			System.out.println("");
			
			return;
		}


		if (args.length >0) 
			path = args[0];
		
		if (args.length >1) 
			iCodeText = args[1];
		
		if (args.length >2) 
			ruleImagefile = args[2];
		
		path = "/home/odl/workspace/StandaloneTest/rules";

		System.out.println("Path=" + path );
		System.out.println("iCodeText=" + iCodeText );
		System.out.println("RuleImage=" + ruleImagefile );

		path=implementFullPath(path);
		iCodeText=implementFullPath(iCodeText);
		ruleImagefile=implementFullPath(ruleImagefile);
		
		
		try{
			File f= new File(path);
			if (!f.isDirectory()) {
				System.out.println("Error: \"" + path+ "\" is not a correct path.\n");
				return;
			}
		}catch(Exception e) {
			System.out.println(e.getMessage()+ "\n");
			return;
		}
		
		System.out.println("Starting parsing ......");		

		SnortFileParser.createLionicTemplateFiles(path, iCodeText,ruleImagefile);
		System.out.println("Finished parsing.");
		System.out.println("LIONIC iCode data file is \"" + iCodeText + "\"");
		System.out.println("LIONIC Rule Images file is \"" + ruleImagefile + "\"");
		System.out.println("Good Luck!");
		
	}

}
