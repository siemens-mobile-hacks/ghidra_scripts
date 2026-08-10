// Selectively clears function/decompiler analysis metadata, prototypes and names.
// @category Siepatch

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.Variable;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighFunctionDBUtil;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class ResetFunctionAnalysis extends GhidraScript {
	private static final String RESET_ANALYSIS = "Reset analysis";
	private static final String RESET_PROTOTYPES = "Reset function prototypes";
	private static final String RESET_NAMES = "Reset function names";

	@Override
	protected void run() throws Exception {
		boolean referencesOnly = hasArgument("--xrefs-only");
		boolean resetAnalysis = true;
		boolean resetPrototypes = !referencesOnly;
		boolean resetNames = false;

		if (getScriptArgs().length == 0) {
			GhidraValuesMap values = new GhidraValuesMap();
			values.defineBoolean(RESET_ANALYSIS, true);
			values.defineBoolean(RESET_PROTOTYPES, true);
			values.defineBoolean(RESET_NAMES, false);
			values = askValues("Reset function analysis", "Choose what to reset", values);

			resetAnalysis = values.getBoolean(RESET_ANALYSIS);
			resetPrototypes = values.getBoolean(RESET_PROTOTYPES);
			resetNames = values.getBoolean(RESET_NAMES);
		}

		if (!resetAnalysis && !resetPrototypes && !resetNames) {
			println("Nothing selected; no changes made.");
			return;
		}

		int referencesRemoved = resetAnalysis ? removeAnalysisReferences() : 0;
		if (referencesOnly) {
			println("Reset complete: " + referencesRemoved +
				" analysis-generated xref(s) removed. Function signatures, names, " +
				"bodies and user/imported xrefs were preserved.");
			return;
		}

		List<Function> functions = new ArrayList<>();
		FunctionIterator iterator = currentProgram.getFunctionManager().getFunctions(true);
		while (iterator.hasNext()) {
			functions.add(iterator.next());
		}

		monitor.initialize(functions.size());
		int overridesRemoved = 0;
		int analysisReset = 0;
		int prototypesReset = 0;
		int namesReset = 0;
		int failures = 0;

		for (Function function : functions) {
			monitor.checkCancelled();
			monitor.setMessage("Resetting " + function.getName());

			try {
				if (resetAnalysis && !function.isThunk()) {
					for (Variable local : function.getLocalVariables()) {
						function.removeVariable(local);
					}
					function.setNoReturn(false);
					function.setInline(false);
					function.setCallFixup(null);
					function.setStackPurgeSize(Function.UNKNOWN_STACK_DEPTH_CHANGE);
					analysisReset++;
				}

				if (resetPrototypes) {
					overridesRemoved += removePrototypeOverrides(function);
					if (!function.isThunk()) {
						function.updateFunction(Function.DEFAULT_CALLING_CONVENTION_STRING,
							new ReturnParameterImpl(Undefined1DataType.dataType, currentProgram),
							List.of(), FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS, true,
							SourceType.DEFAULT);
						function.setVarArgs(false);
						function.setSignatureSource(SourceType.DEFAULT);
						prototypesReset++;
					}
				}

				if (resetNames && function.getSymbol().getSource() != SourceType.DEFAULT) {
					function.setName("", SourceType.DEFAULT);
					namesReset++;
				}
			}
			catch (Exception exception) {
				failures++;
				printerr(function.getEntryPoint() + " " + function.getName() + ": " +
					exception.getMessage());
			}
			monitor.incrementProgress(1);
		}

		println("Reset complete: " + analysisReset + " function analysis record(s), " +
			prototypesReset + " function prototype(s), " + namesReset + " function name(s), " +
			overridesRemoved + " prototype override(s), and " + referencesRemoved +
			" analysis-generated xref(s) reset; " + failures + " failure(s). Function bodies, " +
			"labels, comments and user/imported xrefs were preserved.");
	}

	private boolean hasArgument(String expected) {
		for (String argument : getScriptArgs()) {
			if (expected.equals(argument)) {
				return true;
			}
		}
		return false;
	}

	private int removeAnalysisReferences() throws Exception {
		ReferenceManager manager = currentProgram.getReferenceManager();
		List<Reference> references = new ArrayList<>();
		AddressIterator sources =
			manager.getReferenceSourceIterator(currentProgram.getMinAddress(), true);
		while (sources.hasNext()) {
			monitor.checkCancelled();
			for (Reference reference : manager.getReferencesFrom(sources.next())) {
				if (reference.getSource() == SourceType.ANALYSIS) {
					references.add(reference);
				}
			}
		}

		monitor.setMessage("Removing analysis-generated xrefs");
		for (Reference reference : references) {
			monitor.checkCancelled();
			manager.delete(reference);
		}
		return references.size();
	}

	private int removePrototypeOverrides(Function function) {
		Namespace overrideSpace = HighFunction.findOverrideSpace(function);
		if (overrideSpace == null) {
			return 0;
		}

		List<Symbol> prototypeSymbols = new ArrayList<>();
		SymbolIterator symbols = currentProgram.getSymbolTable().getSymbols(overrideSpace);
		while (symbols.hasNext()) {
			Symbol symbol = symbols.next();
			if (HighFunctionDBUtil.readOverride(symbol) != null) {
				prototypeSymbols.add(symbol);
			}
		}

		int removed = 0;
		for (Symbol symbol : prototypeSymbols) {
			if (symbol.delete()) {
				removed++;
			}
		}
		return removed;
	}
}
