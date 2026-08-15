// Exports functions and labels from selected memory blocks.
// @category Siepatch

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.Dimension;
import java.awt.Font;
import java.io.BufferedWriter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import javax.swing.BorderFactory;
import javax.swing.Box;
import javax.swing.BoxLayout;
import javax.swing.JCheckBox;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ScrollPaneConstants;

import docking.DialogComponentProvider;
import docking.DockingWindowManager;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.model.symbol.SymbolUtilities;
import ghidra.util.exception.CancelledException;

public class ExportSymbolsWithDataType extends GhidraScript {
	private static final String FUNCTIONS = "Functions";
	private static final String LABELS = "Labels";
	private static final String WITH_DATA_TYPES = "With data types";
	private static final String AUTOMATICALLY_GENERATED_SYMBOLS =
		"Automatically generated symbols (like FUN_123)";

	private static class BlockOption {
		private final MemoryBlock block;
		private final String label;

		BlockOption(MemoryBlock block, String label) {
			this.block = block;
			this.label = label;
		}
	}

	private static class ExportOptions {
		private final List<MemoryBlock> blocks;
		private final boolean withFunctions;
		private final boolean withLabels;
		private final boolean withDataTypes;
		private final boolean withAutomaticallyGeneratedSymbols;

		ExportOptions(List<MemoryBlock> blocks, boolean withFunctions, boolean withLabels,
				boolean withDataTypes, boolean withAutomaticallyGeneratedSymbols) {
			this.blocks = blocks;
			this.withFunctions = withFunctions;
			this.withLabels = withLabels;
			this.withDataTypes = withDataTypes;
			this.withAutomaticallyGeneratedSymbols = withAutomaticallyGeneratedSymbols;
		}
	}

	private static class ExportOptionsDialog extends DialogComponentProvider {
		private final JCheckBox withFunctions = new JCheckBox(FUNCTIONS, true);
		private final JCheckBox withLabels = new JCheckBox(LABELS, false);
		private final JCheckBox withDataTypes = new JCheckBox(WITH_DATA_TYPES, true);
		private final JCheckBox withAutomaticallyGeneratedSymbols =
			new JCheckBox(AUTOMATICALLY_GENERATED_SYMBOLS, false);
		private final List<BlockOption> options;
		private final List<JCheckBox> blockCheckBoxes = new ArrayList<>();
		private boolean cancelled = true;

		ExportOptionsDialog(List<BlockOption> options, MemoryBlock currentBlock,
				boolean selectAllByDefault) {
			super("Export symbols");
			this.options = options;

			JPanel content = new JPanel();
			content.setLayout(new BoxLayout(content, BoxLayout.Y_AXIS));
			content.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
			withFunctions.setAlignmentX(Component.LEFT_ALIGNMENT);
			withLabels.setAlignmentX(Component.LEFT_ALIGNMENT);
			withDataTypes.setAlignmentX(Component.LEFT_ALIGNMENT);
			withAutomaticallyGeneratedSymbols.setAlignmentX(Component.LEFT_ALIGNMENT);
			content.add(withFunctions);
			content.add(withLabels);
			content.add(withDataTypes);
			content.add(withAutomaticallyGeneratedSymbols);
			withFunctions.addActionListener(
				event -> withDataTypes.setEnabled(withFunctions.isSelected()));
			content.add(Box.createVerticalStrut(12));

			JLabel memoryRegions = new JLabel("Memory regions:");
			memoryRegions.setFont(memoryRegions.getFont().deriveFont(Font.BOLD));
			memoryRegions.setAlignmentX(Component.LEFT_ALIGNMENT);
			content.add(memoryRegions);
			content.add(Box.createVerticalStrut(4));

			JPanel blocksPanel = new JPanel();
			blocksPanel.setLayout(new BoxLayout(blocksPanel, BoxLayout.Y_AXIS));
			for (BlockOption option : options) {
				boolean selected = selectAllByDefault || option.block.equals(currentBlock);
				JCheckBox checkBox = new JCheckBox(option.label, selected);
				checkBox.setAlignmentX(Component.LEFT_ALIGNMENT);
				blockCheckBoxes.add(checkBox);
				blocksPanel.add(checkBox);
			}

			JScrollPane blocksScroll = new JScrollPane(blocksPanel,
				ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,
				ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);
			blocksScroll.setAlignmentX(Component.LEFT_ALIGNMENT);
			int height = Math.min(360, Math.max(100, options.size() * 24 + 8));
			blocksScroll.setPreferredSize(new Dimension(620, height));
			content.add(blocksScroll);

			JPanel wrapper = new JPanel(new BorderLayout());
			wrapper.add(content, BorderLayout.CENTER);
			addWorkPanel(wrapper);
			addOKButton();
			addCancelButton();
			setRememberSize(false);
		}

		@Override
		protected void okCallback() {
			cancelled = false;
			close();
		}

		boolean wasCancelled() {
			return cancelled;
		}

		ExportOptions getOptions() {
			List<MemoryBlock> selected = new ArrayList<>();
			for (int i = 0; i < options.size(); i++) {
				if (blockCheckBoxes.get(i).isSelected()) {
					selected.add(options.get(i).block);
				}
			}
			return new ExportOptions(selected, withFunctions.isSelected(), withLabels.isSelected(),
				withDataTypes.isSelected(), withAutomaticallyGeneratedSymbols.isSelected());
		}
	}

	private static class ExportItem {
		private final String type;
		private final Address address;
		private final String name;
		private final String dataType;

		ExportItem(String type, Address address, String name, String dataType) {
			this.type = type;
			this.address = address;
			this.name = name;
			this.dataType = dataType;
		}
	}

	@Override
	protected void run() throws Exception {
		ExportOptions options = chooseOptions();
		if (!options.withFunctions && !options.withLabels) {
			println("Neither functions nor labels selected; no symbols exported.");
			return;
		}
		if (options.blocks.isEmpty()) {
			println("Nothing selected; no symbols exported.");
			return;
		}

		File output = askFile("Choose symbols export file", "Export");
		if (output.exists() &&
			!askYesNo("Overwrite symbols file?", "The file already exists:\n" + output)) {
			println("Export cancelled; existing file was not changed.");
			return;
		}

		AddressSet addresses = new AddressSet();
		for (MemoryBlock block : options.blocks) {
			addresses.add(block.getStart(), block.getEnd());
		}

		monitor.setIndeterminate(true);
		monitor.setMessage("Collecting functions and labels");
		List<ExportItem> items = collectItems(addresses, options.withFunctions,
			options.withLabels, options.withDataTypes,
			options.withAutomaticallyGeneratedSymbols);
		items.sort(Comparator
			.comparing((ExportItem item) -> item.address)
			.thenComparing(item -> item.type)
			.thenComparing(item -> item.name)
			.thenComparing(item -> item.dataType));

		int functionCount = 0;
		int labelCount = 0;
		try (BufferedWriter writer = Files.newBufferedWriter(output.toPath(),
			StandardCharsets.UTF_8, StandardOpenOption.CREATE,
			StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)) {
			for (ExportItem item : items) {
				monitor.checkCancelled();
				writer.write(item.type);
				writer.write('\t');
				writer.write(formatAddress(item.address));
				writer.write('\t');
				writer.write(item.name);
				if (!item.dataType.isEmpty()) {
					writer.write('\t');
					writer.write(item.dataType);
				}
				writer.newLine();

				if ("F".equals(item.type)) {
					functionCount++;
				}
				else {
					labelCount++;
				}
			}
		}

		println("Exported " + functionCount + " function(s) and " + labelCount +
			" label(s) from " + options.blocks.size() + " memory block(s) to " +
			output.getAbsolutePath());
	}

	private ExportOptions chooseOptions() throws CancelledException {
		AddressSpace defaultSpace = currentProgram.getAddressFactory().getDefaultAddressSpace();
		MemoryBlock currentBlock = currentAddress == null ? null :
			currentProgram.getMemory().getBlock(currentAddress);
		List<BlockOption> options = new ArrayList<>();
		int index = 1;

		for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
			if (!defaultSpace.equals(block.getStart().getAddressSpace())) {
				continue;
			}
			String label = String.format("%02d. %s [%s - %s]", index++, block.getName(),
				block.getStart(), block.getEnd());
			options.add(new BlockOption(block, label));
		}

		if (options.isEmpty()) {
			throw new IllegalStateException("The program has no memory blocks in its default address space.");
		}

		boolean selectAllByDefault = currentBlock == null ||
			!defaultSpace.equals(currentBlock.getStart().getAddressSpace());
		ExportOptionsDialog dialog =
			new ExportOptionsDialog(options, currentBlock, selectAllByDefault);
		DockingWindowManager.showDialog(dialog);
		if (dialog.wasCancelled()) {
			throw new CancelledException();
		}
		return dialog.getOptions();
	}

	private List<ExportItem> collectItems(AddressSet addresses, boolean withFunctions,
			boolean withLabels, boolean withDataTypes,
			boolean withAutomaticallyGeneratedSymbols) throws Exception {
		List<ExportItem> items = new ArrayList<>();
		Set<String> seen = new HashSet<>();

		if (withFunctions) {
			FunctionIterator functions = currentProgram.getFunctionManager().getFunctions(true);
			while (functions.hasNext()) {
				monitor.checkCancelled();
				Function function = functions.next();
				Address entry = function.getEntryPoint();
				if (!addresses.contains(entry) ||
					(!withAutomaticallyGeneratedSymbols && !isExplicitFunction(function))) {
					continue;
				}

				String dataType = withDataTypes ? function.getPrototypeString(true, false) : "";
				addItem(items, seen, new ExportItem("F", entry, function.getName(), dataType));
			}
		}

		if (withLabels) {
			SymbolIterator symbols = currentProgram.getSymbolTable().getAllSymbols(
				withAutomaticallyGeneratedSymbols);
			while (symbols.hasNext()) {
				monitor.checkCancelled();
				Symbol symbol = symbols.next();
				if (symbol.getSymbolType() == SymbolType.LABEL &&
					addresses.contains(symbol.getAddress()) &&
					(withAutomaticallyGeneratedSymbols || isExplicit(symbol))) {
					addItem(items, seen,
						new ExportItem("L", symbol.getAddress(), symbol.getName(), ""));
				}
			}
		}
		return items;
	}

	private boolean isExplicitFunction(Function function) {
		if (!isExplicit(function.getSymbol())) {
			return false;
		}
		// Old or imported databases can retain an explicit source on a standard
		// Ghidra function name.  The option promises to exclude FUN_<address>, so
		// do not rely on SourceType alone.
		String defaultName = SymbolUtilities.getDefaultFunctionName(function.getEntryPoint());
		return !defaultName.equals(function.getName());
	}

	private boolean isExplicit(Symbol symbol) {
		SourceType source = symbol.getSource();
		return source == SourceType.USER_DEFINED || source == SourceType.IMPORTED;
	}

	private void addItem(List<ExportItem> items, Set<String> seen, ExportItem item) {
		String key = item.type + "\0" + item.address + "\0" + item.name + "\0" + item.dataType;
		if (seen.add(key)) {
			items.add(item);
		}
	}

	private String formatAddress(Address address) {
		return Long.toHexString(address.getOffset()).toUpperCase(Locale.ROOT);
	}
}
