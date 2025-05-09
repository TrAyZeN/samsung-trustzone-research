package mclfloader;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class MCLFLoader extends AbstractLibrarySupportLoader {
    public MCLFHeader header;
    public MCLFTextHeader textHeader;

    @Override
    public String getName() {
        return "MobiCore Loadable Format (MCLF)";
    }

    @Override
    public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
        BinaryReader reader = new BinaryReader(provider, true);
        if (reader.readNextAsciiString(4).equals("MCLF"))
            return List.of(
                new LoadSpec(this, 0, new LanguageCompilerSpecPair("ARM:LE:32:v7", "default"), true),
                new LoadSpec(this, 0, new LanguageCompilerSpecPair("AARCH64:LE:64:v8A", "default"), true),
                new LoadSpec(this, 0, new LanguageCompilerSpecPair("AARCH64:LE:32:v8A", "default"), true)
            );
        return new ArrayList<>();
    }

    @Override
    protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options, Program program,
            TaskMonitor monitor, MessageLog log) throws CancelledException, IOException {
        BinaryReader reader = new BinaryReader(provider, true);
        FlatProgramAPI api = new FlatProgramAPI(program, monitor);

        header = new MCLFHeader(api, reader);
        textHeader = new MCLFTextHeader(api, reader);

        Address textVa = api.toAddr(header.textStart);
        Address dataVa = api.toAddr(header.dataStart);
        Address entry = api.toAddr(header.entry);

        InputStream input = provider.getInputStream(0);
        createSegment(api, input, ".text", textVa, header.textLen, true, false, true);
        createSegment(api, input, ".data", dataVa, header.dataLen, true, true, false);
        createSegment(api, null, ".bss", dataVa.add(header.dataLen), header.bssLen, true, true, false);

        api.addEntryPoint(entry);
        api.createFunction(entry, "_entry");

        try {
            api.createLabel(textVa.add(0x8c), "tlApiLibEntry", true);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }

        try {
            DataUtilities.createData(program, textVa, header.toDataType(), -1, false,
                    ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        } catch (CodeUnitInsertionException e) {
            Msg.error(this, e.getMessage());
        }

        try {
            DataUtilities.createData(program, textVa.add(0x80), textHeader.toDataType(), -1, false,
                    ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA);
        } catch (CodeUnitInsertionException e) {
            Msg.error(this, e.getMessage());
        }
    }

    private void createSegment(FlatProgramAPI api, InputStream input, String name, Address start, long length,
            boolean read, boolean write, boolean exec) {
        try {
            MemoryBlock text = api.createMemoryBlock(name, start, input, length, false);
            text.setRead(read);
            text.setWrite(write);
            text.setExecute(exec);
        } catch (Exception e) {
            Msg.error(this, e.getMessage());
        }
    }
}
