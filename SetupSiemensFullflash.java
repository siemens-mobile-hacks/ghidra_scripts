// @category Siepatch

/**
Prepares a Siemens fullflash for analysis, following https://siepatch.dev/docs/reverse-engineering/how-start

Run it on a fullflash imported as Raw Binary, ARM v5t 32 little, base address A0000000, without auto-analysis.
In the GUI the script sets up the open program or asks for a fullflash .bin, imports it that way and opens it;
the fullflash=FILE argument imports and opens a fullflash without asking.
The script then:
- makes the flash read-only;
- creates the IO block at F0000000;
- imports memory dumps named NAME_START_SIZE.bin or NAME_START_END.bin (hex), for example EL71v45_RAM_A8000000_01000000.bin
  or EL71v45-RAM-A8000000_01000000.bin from sie-tool, given as files or directories;
- applies the analysis options;
- imports swilib types, CPU registers and firmware symbols, downloading from devtools.siepatch.dev the files not given;
- runs auto-analysis and a one-shot "Create Address Tables".

The swilib target and platform are detected from the firmware model; CPU registers follow the target model.
In the GUI a dialog shows the detected values and lets you override them and choose local files.
With script arguments (headless, Ghidra MCP) the script asks nothing; pass overrides as arguments:
	analyzeHeadless PROJECT_DIR PROJECT -import fullflash.bin -loader BinaryLoader \
		-loader-baseAddr 0xA0000000 -loader-blockName FULLFLASH -processor ARM:LE:32:v5t -noanalysis \
		-scriptPath ghidra_scripts -postScript SetupSiemensFullflash.java [fullflash=FILE] [dumps=FILE_OR_DIR[:...]] [target=EL71v45|none] \
		[platform=ELKA|NSG|X75|SG] [types=swilib-types.h] [cpu=cpu.txt] [symbols=symbols.txt] [analyze=false]
*/
import java.awt.BorderLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;
import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.script.GhidraScript;
import ghidra.app.services.ProgramManager;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.app.util.cparser.C.CParserUtils.CParseResults;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.BinaryLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramFragment;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.Swing;
import ghidra.util.exception.CancelledException;

public class SetupSiemensFullflash extends GhidraScript {
	private static final String API_URL = "https://api.siepatch.dev/swilib-tools/api";
	private static final long FLASH_BASE = 0xA0000000L;
	private static final long IO_BASE = 0xF0000000L;
	private static final long IO_SIZE = 0x0F000000L;
	private static final long RAM_BASE = 0xA8000000L;
	private static final long[] VENDOR_OFFSETS = { 0x8FC80, 0x220, 0x880, 0xC80 };
	private static final double MIN_PROLOGUE_RATIO = 0.5;
	private static final Pattern DUMP_NAME = Pattern.compile("(?:.*[_-])?([A-Za-z0-9]+)[_-]([0-9A-Fa-f]{8})_([0-9A-Fa-f]{8})\\.bin");
	private static final Pattern JSON_OBJECT = Pattern.compile("\\{[^{}]*\\}");
	private static final Pattern JSON_FIELD = Pattern.compile("\"(\\w+)\"\\s*:\\s*\"?([^\",}]*)");
	private static final List<String> PLATFORMS = List.of("ELKA", "NSG", "X75", "SG");
	private static final String[] PARSER_ARGS = { "-D__builtin_va_list=void *" };
	private static final String LANGUAGE = "ARM:LE:32:v5t";
	private static final String COMPILER = "default";
	private static final String NO_TARGET = "none";
	private static final String IMPORT_CHOICE = "Import another fullflash .bin";
	private static final Map<String, String> ANALYSIS_OPTIONS = Map.of(
		"Embedded Media", "false",
		"Non-Returning Functions - Discovered", "false",
		"Create Address Tables", "false",
		"Demangler GNU", "false",
		"Scalar Operand References", "true",
		"Shared Return Calls", "true",
		"Shared Return Calls.Allow Conditional Jumps", "true"
	);

	private record Device(String target, String model, String platform) {}

	private static class Options {
		String target;
		String platform;
		File types;
		File cpu;
		File symbols;
		List<File> dumps = new ArrayList<>();
		boolean analyze;
	}

	private static class OptionsDialog extends DialogComponentProvider {
		private final JComboBox<String> m_target;
		private final JComboBox<String> m_platform;
		private final JTextField m_dumps = new JTextField(40);
		private final JCheckBox m_analyze = new JCheckBox("Run auto-analysis");
		private final JCheckBox m_advanced = new JCheckBox("Advanced options");
		private final JTextField m_types = new JTextField(40);
		private final JTextField m_cpu = new JTextField(40);
		private final JTextField m_symbols = new JTextField(40);
		private boolean m_confirmed;

		OptionsDialog(Options options, List<String> targets) {
			super("Setup Siemens fullflash");
			m_target = new JComboBox<>(targets.toArray(new String[0]));
			m_target.setSelectedItem(options.target == null ? NO_TARGET : options.target);
			m_platform = new JComboBox<>(PLATFORMS.toArray(new String[0]));
			m_platform.setSelectedItem(options.platform == null ? PLATFORMS.get(0) : options.platform);
			m_dumps.setText(joinPaths(options.dumps));
			m_analyze.setSelected(options.analyze);
			m_types.setText(getPath(options.types));
			m_cpu.setText(getPath(options.cpu));
			m_symbols.setText(getPath(options.symbols));

			JPanel firmware = createSection("Firmware");
			addRow(firmware, 0, "Swilib target:", m_target);
			addRow(firmware, 1, "Platform:", m_platform);
			addRow(firmware, 2, "", new JLabel("Types, CPU registers and symbols are downloaded from devtools.siepatch.dev."));

			JPanel dumps = createSection("Memory dumps");
			addRow(dumps, 0, "Files or folders:", createPathField(m_dumps, GhidraFileChooserMode.FILES_AND_DIRECTORIES, true));
			addRow(dumps, 1, "", new JLabel("<html>The file name gives the region start and its size or end in hex:<br>"
				+ "NAME_START_SIZE.bin or NAME_START_END.bin, for example<br>"
				+ "RAM_A8000000_01000000.bin or EL71v45_VMALLOC_AC000000_AD800000.bin.</html>"));

			JPanel flags = new JPanel();
			flags.setLayout(new BoxLayout(flags, BoxLayout.Y_AXIS));
			flags.add(m_analyze);
			flags.add(m_advanced);

			JPanel files = createSection("Local files instead of downloads");
			addRow(files, 0, "Swilib types .h:", createPathField(m_types, GhidraFileChooserMode.FILES_ONLY, false));
			addRow(files, 1, "CPU registers .txt:", createPathField(m_cpu, GhidraFileChooserMode.FILES_ONLY, false));
			addRow(files, 2, "Swilib symbols .txt:", createPathField(m_symbols, GhidraFileChooserMode.FILES_ONLY, false));
			boolean hasFiles = options.types != null || options.cpu != null || options.symbols != null;
			m_advanced.setSelected(hasFiles);
			files.setVisible(hasFiles);
			m_advanced.addActionListener(event -> {
				files.setVisible(m_advanced.isSelected());
				repack();
			});

			JPanel content = new JPanel();
			content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
			content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
			for (JComponent section : List.of(firmware, dumps, flags, files)) {
				section.setAlignmentX(JComponent.LEFT_ALIGNMENT);
				content.add(section);
			}
			addWorkPanel(content);
			addOKButton();
			addCancelButton();
			setRememberSize(false);
		}

		@Override
		protected void okCallback() {
			m_confirmed = true;
			close();
		}

		boolean isConfirmed() {
			return m_confirmed;
		}

		void apply(Options options) {
			String target = (String) m_target.getSelectedItem();
			options.target = target.equals(NO_TARGET) ? null : target;
			options.platform = (String) m_platform.getSelectedItem();
			options.dumps = parsePaths(m_dumps.getText());
			options.analyze = m_analyze.isSelected();
			boolean advanced = m_advanced.isSelected();
			options.types = advanced ? getFile(m_types) : null;
			options.cpu = advanced ? getFile(m_cpu) : null;
			options.symbols = advanced ? getFile(m_symbols) : null;
		}

		private JPanel createPathField(JTextField field, GhidraFileChooserMode mode, boolean multiple) {
			JButton browse = new JButton("...");
			browse.addActionListener(event -> {
				GhidraFileChooser chooser = new GhidraFileChooser(getComponent());
				chooser.setFileSelectionMode(mode);
				chooser.setMultiSelectionEnabled(multiple);
				List<File> files = chooser.getSelectedFiles();
				if (!files.isEmpty()) {
					field.setText(joinPaths(files));
				}
				chooser.dispose();
			});

			JPanel panel = new JPanel(new BorderLayout(4, 0));
			panel.add(field, BorderLayout.CENTER);
			panel.add(browse, BorderLayout.EAST);
			return panel;
		}

		private static JPanel createSection(String title) {
			JPanel section = new JPanel(new GridBagLayout());
			section.setBorder(BorderFactory.createTitledBorder(title));
			return section;
		}

		private static void addRow(JPanel panel, int row, String label, JComponent component) {
			GridBagConstraints constraints = new GridBagConstraints();
			constraints.gridy = row;
			constraints.gridx = 0;
			constraints.anchor = GridBagConstraints.WEST;
			constraints.insets = new Insets(2, 2, 2, 8);
			panel.add(new JLabel(label), constraints);

			constraints.gridx = 1;
			constraints.weightx = 1;
			constraints.fill = GridBagConstraints.HORIZONTAL;
			constraints.insets = new Insets(2, 0, 2, 2);
			panel.add(component, constraints);
		}

		private static String getPath(File file) {
			return file == null ? "" : file.getPath();
		}

		private static File getFile(JTextField field) {
			String path = field.getText().trim();
			return path.isEmpty() ? null : new File(path);
		}
	}

	private final HttpClient m_http = HttpClient.newHttpClient();
	private final Map<String, String> m_args = new HashMap<>();
	private Path m_downloadDir;
	private long m_flashSize;

	@Override
	protected void run() throws Exception {
		for (String arg : getScriptArgs()) {
			String[] pair = arg.split("=", 2);
			m_args.put(pair[0], pair.length > 1 ? pair[1] : "");
		}
		m_downloadDir = Files.createTempDirectory("siepatch-ghidra");
		try {
			setupFullflash();
		} finally {
			try (Stream<Path> files = Files.list(m_downloadDir)) {
				for (Path file : files.toList()) {
					Files.delete(file);
				}
			}
			Files.delete(m_downloadDir);
		}
	}

	private void setupFullflash() throws Exception {
		File file = getFileArg("fullflash");
		if (file == null && isInteractive()) {
			file = askFullflashFile();
		}
		if (file == null) {
			if (currentProgram == null) {
				throw new IllegalStateException("Open a fullflash or pass fullflash=FILE");
			}
			setupProgram();
			return;
		}

		Program scriptProgram = currentProgram;
		Program program = importFullflash(file);
		int transaction = program.startTransaction("Setup Siemens fullflash");
		try {
			setupProgram();
		} finally {
			program.endTransaction(transaction, true);
			program.save("Setup Siemens fullflash", monitor);
			program.release(this);
			currentProgram = scriptProgram;
			getState().setCurrentProgram(scriptProgram);
		}
	}

	private boolean isInteractive() {
		return !isRunningHeadless() && m_args.isEmpty();
	}

	private File askFullflashFile() throws Exception {
		if (currentProgram != null) {
			String current = "Current program: " + currentProgram.getName();
			String choice = askChoice("Setup Siemens fullflash", "Fullflash to set up:", List.of(current, IMPORT_CHOICE), current);
			if (choice.equals(current)) {
				return null;
			}
		}
		return askFile("Siemens fullflash .bin", "Import");
	}

	private Program importFullflash(File file) throws Exception {
		try (LoadResults<Program> results = ProgramLoader.builder()
			.source(file)
			.project(getState().getProject())
			.loaders(BinaryLoader.class)
			.language(LANGUAGE)
			.compiler(COMPILER)
			.addLoaderArg("-loader-baseAddr", String.format("0x%08X", FLASH_BASE))
			.addLoaderArg("-loader-blockName", "FULLFLASH")
			.monitor(monitor)
			.load()
		) {
			results.save(monitor);
			Program program = results.getPrimaryDomainObject(this);
			if (!isRunningHeadless()) {
				showInCodeBrowser(program);
			}
			currentProgram = program;
			getState().setCurrentProgram(program);
			return program;
		}
	}

	private void showInCodeBrowser(Program program) {
		GhidraProgramUtilities.markProgramNotToAskToAnalyze(program);
		Project project = getState().getProject();
		PluginTool tool = Arrays.stream(project.getToolManager().getRunningTools())
			.filter(running -> running.getService(ProgramManager.class) != null)
			.findFirst()
			.orElse(null);
		if (tool == null) {
			Swing.runNow(() -> project.getToolServices().launchDefaultTool(List.of(program.getDomainFile())));
			return;
		}
		ProgramManager programManager = tool.getService(ProgramManager.class);
		Swing.runNow(() -> programManager.openProgram(program));
	}

	private void setupProgram() throws Exception {
		Address base = toAddr(FLASH_BASE);
		MemoryBlock flash = getMemoryBlock(base);
		if (flash == null || !flash.getStart().equals(base)) {
			throw new IllegalStateException("Import the fullflash as Raw Binary at A0000000");
		}
		long flashEnd = currentProgram.getMemory().getRangeContaining(base).getMaxAddress().getOffset() + 1;
		m_flashSize = Math.min(flashEnd, RAM_BASE) - FLASH_BASE;

		List<Device> devices = fetchDevices();
		Options options = detectOptions(devices);
		if (isInteractive()) {
			askOptions(options, devices);
		}
		if (!PLATFORMS.contains(options.platform)) {
			throw new IllegalArgumentException("Platform is unknown: choose it in the dialog or pass platform=" + String.join("|", PLATFORMS));
		}
		println("Swilib target: " + options.target + ", platform: " + options.platform);

		setupFlash(flash);
		createIoBlock();
		importDumps(options.dumps);
		renameTreeFragments();
		AutoAnalysisManager.getAnalysisManager(currentProgram).registerAnalyzerOptions();
		setAnalysisOptions(currentProgram, ANALYSIS_OPTIONS);

		importTypes(options.types != null ? options.types.toPath() : downloadTypes(options.platform));
		Path cpu = options.cpu != null ? options.cpu.toPath() : downloadCpuSymbols(getTargetModel(devices, options.target), options.platform);
		runScript("ImportSymbolsWithDataType.java", new String[] { cpu.toString() });
		Path symbols = options.symbols != null ? options.symbols.toPath() : null;
		if (symbols == null && options.target != null) {
			symbols = downloadSymbols(options.target);
		}
		if (symbols != null) {
			runScript("ImportSymbolsWithDataType.java", new String[] { symbols.toString() });
		}

		if (options.analyze) {
			analyzeAll(currentProgram);
			createAddressTables();
		}
	}

	private void setupFlash(MemoryBlock flash) throws Exception {
		flash.setName("FULLFLASH");
		flash.setPermissions(true, false, true);
		flash.setVolatile(false);
	}

	private void renameTreeFragments() throws Exception {
		Listing listing = currentProgram.getListing();
		String tree = listing.getDefaultRootModule().getTreeName();
		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			ProgramFragment fragment = listing.getFragment(tree, block.getStart());
			if (fragment != null && !fragment.getName().equals(block.getName())) {
				fragment.setName(block.getName());
			}
		}
	}

	private void createIoBlock() throws Exception {
		Address base = toAddr(IO_BASE);
		if (getMemoryBlock(base) != null) {
			return;
		}
		MemoryBlock io = currentProgram.getMemory().createUninitializedBlock("IO", base, IO_SIZE, false);
		io.setPermissions(true, true, false);
		io.setVolatile(true);
	}

	private void importDumps(List<File> paths) throws Exception {
		List<File> files = new ArrayList<>();
		for (File path : paths) {
			if (!path.isDirectory()) {
				files.add(path);
				continue;
			}
			File[] children = path.listFiles();
			if (children == null) {
				throw new IOException("Can't list " + path);
			}
			Arrays.sort(children);
			for (File child : children) {
				if (DUMP_NAME.matcher(child.getName()).matches()) {
					files.add(child);
				}
			}
		}

		for (File file : files) {
			Matcher matcher = DUMP_NAME.matcher(file.getName());
			if (!matcher.matches()) {
				println("Skip " + file.getName() + ": the name is not NAME_START_SIZE.bin or NAME_START_END.bin");
				continue;
			}
			String name = matcher.group(1);
			long start = Long.parseLong(matcher.group(2), 16);
			long sizeOrEnd = Long.parseLong(matcher.group(3), 16);
			long size = file.length();
			if (size != sizeOrEnd && size != sizeOrEnd - start) {
				println("Skip " + file.getName() + ": file size " + Long.toHexString(size) + " matches neither size nor end");
				continue;
			}

			Address address = toAddr(start);
			if (getMemoryBlock(address) != null) {
				println("Skip " + file.getName() + ": " + address + " is already mapped");
				continue;
			}

			try (InputStream input = new FileInputStream(file)) {
				MemoryBlock block = currentProgram.getMemory().createInitializedBlock(name, address, input, size, monitor, false);
				configureDumpBlock(block);
			}
			println(String.format("Imported %s at %08X, size %08X", name, start, size));
		}
	}

	private void configureDumpBlock(MemoryBlock block) {
		switch (block.getName()) {
			case "BROM":
				block.setPermissions(true, false, true);
				break;
			case "TCM":
			case "SRAM":
				block.setPermissions(true, true, true);
				block.setVolatile(true);
				break;
			default:
				block.setPermissions(true, true, false);
				block.setVolatile(true);
				break;
		}
	}

	private String readModel() throws Exception {
		for (long offset : VENDOR_OFFSETS) {
			String vendor = readCString(offset, 16);
			if ("SIEMENS".equals(vendor) || "BENQ-SIEMENS".equals(vendor)) {
				return readCString(offset - 16, 16);
			}
		}
		return null;
	}

	private String readCString(long offset, int maxLength) throws Exception {
		if (offset + maxLength > m_flashSize) {
			return null;
		}
		byte[] bytes = getBytes(toAddr(FLASH_BASE + offset), maxLength);
		for (int length = 0; length < maxLength; length++) {
			if (bytes[length] == 0) {
				return new String(bytes, 0, length);
			}
		}
		return null;
	}

	private List<Device> fetchDevices() throws Exception {
		List<Device> devices = new ArrayList<>();
		List<Map<String, String>> objects;
		try {
			objects = fetchObjects("/swilib/devices");
		} catch (IOException e) {
			println("Can't fetch swilib targets: " + e.getMessage());
			return devices;
		}
		for (Map<String, String> object : objects) {
			devices.add(new Device(object.get("target"), object.get("model"), object.get("platform")));
		}
		return devices;
	}

	private Options detectOptions(List<Device> devices) throws Exception {
		Options options = new Options();
		String model = readModel();
		println("Firmware model: " + model);
		options.types = getFileArg("types");
		options.cpu = getFileArg("cpu");
		options.symbols = getFileArg("symbols");
		options.dumps = parsePaths(m_args.getOrDefault("dumps", ""));
		options.analyze = !"false".equals(m_args.get("analyze"));

		if (m_args.containsKey("target")) {
			String target = m_args.get("target");
			options.target = target.equals(NO_TARGET) ? null : target;
		} else if (options.symbols == null) {
			options.target = detectTarget(devices, model);
		}

		if (m_args.containsKey("platform")) {
			options.platform = m_args.get("platform");
		} else {
			options.platform = findPlatform(devices, options.target, model);
		}
		return options;
	}

	private static List<File> parsePaths(String text) {
		List<File> files = new ArrayList<>();
		for (String path : text.split(Pattern.quote(File.pathSeparator))) {
			if (!path.isBlank()) {
				files.add(new File(path.trim()));
			}
		}
		return files;
	}

	private static String joinPaths(List<File> files) {
		List<String> paths = new ArrayList<>();
		for (File file : files) {
			paths.add(file.getPath());
		}
		return String.join(File.pathSeparator, paths);
	}

	private File getFileArg(String name) {
		String path = m_args.get(name);
		return path == null || path.isEmpty() ? null : new File(path);
	}

	private String detectTarget(List<Device> devices, String model) throws Exception {
		String best = null;
		double bestRatio = 0;
		for (Device device : devices) {
			if (!device.model().equals(model)) {
				continue;
			}
			double ratio = getPrologueRatio(downloadSymbols(device.target()));
			println(String.format("Symbols %s: %.0f%% function prologues", device.target(), ratio * 100));
			if (ratio > bestRatio) {
				best = device.target();
				bestRatio = ratio;
			}
		}
		if (best == null || bestRatio < MIN_PROLOGUE_RATIO) {
			println("No swilib symbols match this firmware");
			return null;
		}
		return best;
	}

	private String findPlatform(List<Device> devices, String target, String model) {
		for (Device device : devices) {
			if (device.target().equals(target)) {
				return device.platform();
			}
		}
		for (Device device : devices) {
			if (device.model().equals(model)) {
				return device.platform();
			}
		}
		return null;
	}

	private double getPrologueRatio(Path symbols) throws Exception {
		int functions = 0;
		int prologues = 0;
		for (String line : Files.readAllLines(symbols)) {
			String[] tokens = line.split("\t");
			if (tokens.length < 3 || !tokens[0].equals("F")) {
				continue;
			}
			long offset = (Long.parseLong(tokens[1], 16) & ~1L) - FLASH_BASE;
			if (offset < 0 || offset + 4 > m_flashSize) {
				continue;
			}
			functions++;
			if (isFunctionPrologue(getBytes(toAddr(FLASH_BASE + offset), 4))) {
				prologues++;
			}
		}
		return functions == 0 ? 0 : (double) prologues / functions;
	}

	private boolean isFunctionPrologue(byte[] code) {
		boolean thumbPush = (code[1] & 0xFE) == 0xB4;
		boolean armStmfdSp = (code[3] & 0xFF) == 0xE9 && (code[2] & 0xFF) == 0x2D;
		return thumbPush || armStmfdSp;
	}

	private void askOptions(Options options, List<Device> devices) throws Exception {
		List<String> targets = new ArrayList<>(List.of(NO_TARGET));
		for (Device device : devices) {
			targets.add(device.target());
		}
		if (options.target != null && !targets.contains(options.target)) {
			targets.add(options.target);
		}

		OptionsDialog dialog = new OptionsDialog(options, targets);
		DockingWindowManager.showDialog(dialog);
		if (!dialog.isConfirmed()) {
			throw new CancelledException();
		}
		dialog.apply(options);
	}

	private Path downloadTypes(String platform) throws Exception {
		String name = "swilib-types-" + platform + ".h";
		return download("/disassembler/download/types/" + platform + "/" + name, name);
	}

	private void importTypes(Path header) throws Exception {
		DataTypeManager types = currentProgram.getDataTypeManager();
		CParseResults results = CParserUtils.parseHeaderFiles(new DataTypeManager[0], new String[] { header.toString() },
			new String[0], PARSER_ARGS, types, monitor);
		if (!results.successful()) {
			throw new IllegalStateException("Can't parse " + header + ":\n" + results.getFormattedParseMessage(null));
		}
		println("Imported " + header.getFileName());
	}

	private String getTargetModel(List<Device> devices, String target) {
		for (Device device : devices) {
			if (device.target().equals(target)) {
				return device.model();
			}
		}
		return null;
	}

	private Path downloadCpuSymbols(String model, String platform) throws Exception {
		String cpu = platform.equals("ELKA") || platform.equals("NSG") ? "PMB8876" : "PMB8875";
		String generic = null;
		for (Map<String, String> object : fetchObjects("/disassembler/cpu-symbols")) {
			String name = object.get("name");
			String file = object.get("ghidra");
			if (name.equals(model)) {
				return download("/disassembler/download/cpu/" + file, file);
			}
			if (name.equals(cpu)) {
				generic = file;
			}
		}
		if (generic == null) {
			throw new IllegalStateException("No CPU registers for " + cpu);
		}
		return download("/disassembler/download/cpu/" + generic, generic);
	}

	private Path downloadSymbols(String target) throws Exception {
		String name = "symbols-" + target + ".txt";
		return download("/swilib/download/" + target + "/" + name, name);
	}

	private Path download(String path, String fileName) throws Exception {
		Path file = m_downloadDir.resolve(fileName);
		if (Files.exists(file)) {
			return file;
		}
		HttpRequest request = HttpRequest.newBuilder(URI.create(API_URL + path)).build();
		HttpResponse<Path> response = m_http.send(request, HttpResponse.BodyHandlers.ofFile(file));
		if (response.statusCode() != 200) {
			Files.delete(file);
			throw new IOException("GET " + path + ": HTTP " + response.statusCode());
		}
		return file;
	}

	private List<Map<String, String>> fetchObjects(String path) throws Exception {
		HttpRequest request = HttpRequest.newBuilder(URI.create(API_URL + path)).build();
		HttpResponse<String> response = m_http.send(request, HttpResponse.BodyHandlers.ofString());
		if (response.statusCode() != 200) {
			throw new IOException("GET " + path + ": HTTP " + response.statusCode());
		}
		List<Map<String, String>> objects = new ArrayList<>();
		Matcher object = JSON_OBJECT.matcher(response.body());
		while (object.find()) {
			Map<String, String> fields = new HashMap<>();
			Matcher field = JSON_FIELD.matcher(object.group());
			while (field.find()) {
				fields.put(field.group(1), field.group(2));
			}
			objects.add(fields);
		}
		return objects;
	}

	private void createAddressTables() throws Exception {
		AutoAnalysisManager manager = AutoAnalysisManager.getAnalysisManager(currentProgram);
		manager.scheduleOneTimeAnalysis(manager.getAnalyzer("Create Address Tables"), currentProgram.getMemory().getExecuteSet());
		analyzeChanges(currentProgram);
	}
}
