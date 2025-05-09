package mclfloader;

import java.io.IOException;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.StructConverter;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;

public class MCLFHeader implements StructConverter {
    public char[] magic;
    public long version;
    public long flags;
    public long memType;
    public long serviceType;
    public long numInstances;
    public byte[] uuid;
    public long driverId;
    public long numThreads;
    public long textStart;
    public long textLen;
    public long dataStart;
    public long dataLen;
    public long bssLen;
    public long entry;
    public long serviceVersion;

    public MCLFHeader(FlatProgramAPI api, BinaryReader reader) throws IOException {
        reader.setPointerIndex(0);
        magic = new String(reader.readNextByteArray(4)).toCharArray();
        version = reader.readNextUnsignedInt();
        flags = reader.readNextUnsignedInt();
        memType = reader.readNextUnsignedInt();
        serviceType = reader.readNextUnsignedInt();
        numInstances = reader.readNextUnsignedInt();
        uuid = reader.readNextByteArray(16);
        driverId = reader.readNextUnsignedInt();
        numThreads = reader.readNextUnsignedInt();
        textStart = reader.readNextUnsignedInt();
        textLen = reader.readNextUnsignedInt();
        dataStart = reader.readNextUnsignedInt();
        dataLen = reader.readNextUnsignedInt();
        bssLen = reader.readNextUnsignedInt();
        entry = reader.readNextUnsignedInt();
        serviceVersion = reader.readNextUnsignedInt();
    }

    @Override
    public DataType toDataType() {
        Structure struct = new StructureDataType("mclfHeader_t", 0);
        struct.add(ASCII, 4, "magic", null);
        struct.add(DWORD, 4, "version", null);
        struct.add(DWORD, 4, "flags", null);
        struct.add(DWORD, 4, "memType", null);
        struct.add(DWORD, 4, "serviceType", null);
        struct.add(DWORD, 4, "numInstances", null);
        struct.add(new ArrayDataType(BYTE, 16, 1), "uuid", null);
        struct.add(DWORD, 4, "driverId", null);
        struct.add(DWORD, 4, "numThreads", null);
        struct.add(DWORD, 4, "textStart", null);
        struct.add(DWORD, 4, "textLen", null);
        struct.add(DWORD, 4, "dataStart", null);
        struct.add(DWORD, 4, "dataLen", null);
        struct.add(DWORD, 4, "bssLen", null);
        struct.add(DWORD, 4, "entry", null);
        struct.add(DWORD, 4, "serviceVersion", null);
        return struct;
    }
}
