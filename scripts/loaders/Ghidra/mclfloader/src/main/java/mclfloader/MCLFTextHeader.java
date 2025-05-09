package mclfloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure; import ghidra.program.model.data.StructureDataType;

public class MCLFTextHeader implements StructConverter {
    public long version;
    public long textHeaderLen;
    public long requiredFeat;
    public long mcLibEntry;
    public long mcLibDataStart;
    public long mcLibDataLen;
    public long mcLibHeapSizeInit;
    public long mcLibHeapSizeMax;
    public long tlApiVers;
    public long drApiVers;
    public long taProperties;

    public MCLFTextHeader(FlatProgramAPI api, BinaryReader reader) throws IOException {
        reader.setPointerIndex(0x80);
        version = reader.readNextUnsignedInt();
        textHeaderLen = reader.readNextUnsignedInt();
        requiredFeat = reader.readNextUnsignedInt();
        mcLibEntry = reader.readNextUnsignedInt();
        mcLibDataStart = reader.readNextUnsignedInt();
        mcLibDataLen = reader.readNextUnsignedInt();
        mcLibHeapSizeInit = reader.readNextUnsignedInt();
        mcLibHeapSizeMax = reader.readNextUnsignedInt();
        tlApiVers = reader.readNextUnsignedInt();
        drApiVers = reader.readNextUnsignedInt();
        taProperties = reader.readNextUnsignedInt();
    }

    @Override
    public DataType toDataType() {
        Structure struct = new StructureDataType("mclfTextHeader_t", 0);
        struct.add(DWORD, 4, "version", null);
        struct.add(DWORD, 4, "textHeaderLen", null);
        struct.add(DWORD, 4, "requiredFeat", null);
        struct.add(DWORD, 4, "mcLibEntry", null);
        struct.add(DWORD, 4, "mcLibDataStart", null);
        struct.add(DWORD, 4, "mcLibDataLen", null);
        struct.add(DWORD, 4, "mcLibHeapSizeInit", null);
        struct.add(DWORD, 4, "mcLibHeapSizeMax", null);
        struct.add(DWORD, 4, "tlApiVers", null);
        struct.add(DWORD, 4, "drApiVers", null);
        struct.add(DWORD, 4, "taProperties", null);
        return struct;
    }
}
