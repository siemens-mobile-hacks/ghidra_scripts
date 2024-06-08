/**
Symbols file format:

Function: int (*hello)() = 0xA0000000;
<T>	<ADDRESS>	<NAME>	<TYPE>
F	A0000000	hello	int hello();

Data: int *hello = 0xA8000000;
<T>	<ADDRESS>	<NAME>	<TYPE>
D	A8000000	hello	int

Label
<T>	<ADDRESS>	<NAME>
L	A8000000	hello
*/
import java.io.IOException;
import java.io.File;
import java.io.FileInputStream;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.Vector;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.program.model.util.CodeUnitInsertionException;

public class ImportSymbolsWithDataType extends GhidraScript {
	private DataTypeManager m_dataTypeManager;
	private CParser m_parser;

	private class ParsedItem {
		Address address;
		String name;
		String type;
		DataType dataType;
	};

	@Override
	protected void run() throws CancelledException, DuplicateNameException, InvalidInputException, CodeUnitInsertionException {
		m_dataTypeManager = currentProgram.getDataTypeManager();
		m_parser = new CParser(m_dataTypeManager);

		FunctionManager functionManager = currentProgram.getFunctionManager();
		SymbolTable symbolTable = currentProgram.getSymbolTable();
		Listing listing = currentProgram.getListing();

		File file = askFile("Please select symbols file, for e.g. symbols.txt", "Apply");
		// File file = new File("/tmp/symbols.txt");
		Vector<ParsedItem> items = parseSymbolsList(file);
		println("Parsed " + items.size() + " symbols!");

		println("Remove all old symbols...");
		for (ParsedItem item : items) {
			for (Symbol symbol : symbolTable.getSymbols(item.address)) {
				symbol.delete();
			}
		}

		println("Importing new symbols...");
		for (ParsedItem item : items) {
			if (item.type.equals("F")) {
				// Set label for the address
				symbolTable.createLabel(item.address, item.name, SourceType.USER_DEFINED);

				// Find or create function
				Function func = functionManager.getFunctionAt(item.address);
				if (func == null) {
					clearListing(item.address);
					disassemble(item.address);
					func = createFunction(item.address, item.name);
				}

				// Update function signature
				ApplyFunctionSignatureCmd cmd = new ApplyFunctionSignatureCmd(item.address, (FunctionSignature) item.dataType, SourceType.USER_DEFINED);
				if (!cmd.applyTo(currentProgram, monitor)) {
					println("ApplyFunctionSignatureCmd failed on: " + item.name);
				}
			} else if (item.type.equals("D")) {
				// Set label for the address
				symbolTable.createLabel(item.address, item.name, SourceType.USER_DEFINED);

				Address start = item.address;
				Address end = item.address.add(item.dataType.getLength() - 1);
				if (!isValidAddress(start) || !isValidAddress(end)) {
					println("BAD ADDRESS: " + start.toString());
					continue;
				}

				// Clear old data
				clearListing(new AddressSet(start, end));

				// Create new data
				listing.createData(item.address, item.dataType);
			} else if (item.type.equals("L")) {
				// Set label for the address
				symbolTable.createLabel(item.address, item.name, SourceType.USER_DEFINED);
			}
		}
	}

	protected Vector<ParsedItem> parseSymbolsList(File file) {
		Vector<ParsedItem> symbols = new Vector<ParsedItem>();
		try {
			FileInputStream stream = new FileInputStream(file);
			BufferedReader br = new BufferedReader(new InputStreamReader(stream));

			String line;
			while ((line = br.readLine()) != null)   {
				String[] tokens = line.trim().split("\t");

				ParsedItem symbol = new ParsedItem();

				long addr = Long.parseLong(tokens[1], 16);
				symbol.address = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(addr);
				symbol.name = tokens[2];
				symbol.type = tokens[0];

				if (tokens[0].equals("F")) { // Function
					String code = tokens[3] + ";";
					DataType functionSignature = parseDataType(code);
					if (functionSignature == null) {
						println("BAD: " + code);
					} else {
						symbol.dataType = functionSignature;
						symbols.add(symbol);
					}
				} else if (tokens[0].equals("D")) { // DATA
					String code = tokens[3] + " varName;";
					DataType dataType = parseDataType(code);
					if (dataType == null) {
						println("BAD: " + code);
					} else {
						symbol.dataType = dataType;
						symbols.add(symbol);
					}
				} else if (tokens[0].equals("L")) { // LABEL
					symbols.add(symbol);
				} else {
					println("ERROR: invalid entry type: " + tokens[0]);
				}
			}

			br.close();
			stream.close();
		} catch (IOException e) {
			println("Can't open symbols: " + file.toString());
		}
		return symbols;
	}

	protected DataType parseDataType(String code) {
		DataType type = null;
		try {
			type = m_parser.parse(code);
		} catch (ParseException e) {
			// println("Can't parse `" + code + "`: " + e.toString());
		}
		return type;
	}

	private void renameFunction(Function function, String newName) throws DuplicateNameException, InvalidInputException {
		if (function.getName() == newName)
			return;

		try {
			function.setName(newName, SourceType.USER_DEFINED);
		} catch (DuplicateNameException e) {
			println("DUP: " + newName + " - already exists.");

			SymbolTable symbolTable = currentProgram.getSymbolTable();
			Symbol existingSymbol = symbolTable.getSymbol(newName, function.getEntryPoint(), null);

			String tempName = newName + "_old";
			existingSymbol.setName(tempName, SourceType.USER_DEFINED);
			println("   -> old function renamed to: " + tempName);

			function.setName(newName, SourceType.USER_DEFINED);
		}
	}

	private Function findFunctionByName(String functionName) {
		FunctionManager functionManager = currentProgram.getFunctionManager();
		for (Function function : functionManager.getFunctions(true)) {
			if (function.getName().equals(functionName)) {
				return function;
			}
		}
		return null;
	}

	private boolean isValidAddress(Address address) {
		MemoryBlock block = currentProgram.getMemory().getBlock(address);
		if (block == null) {
			return false;
		}
		return block.contains(address);
	}
};
