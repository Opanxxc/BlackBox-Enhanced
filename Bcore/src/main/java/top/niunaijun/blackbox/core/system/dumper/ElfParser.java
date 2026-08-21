package top.niunaijun.blackbox.core.system.dumper;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * ELF binary parser for extracting sections, symbols, strings with hex offsets.
 * Used by AppDumperService for real binary analysis.
 */
public class ElfParser {

    // ELF magic
    private static final byte[] ELF_MAGIC = {0x7f, 'E', 'L', 'F'};
    private static final int EI_CLASS = 4;
    private static final int EI_DATA = 5;
    private static final int EI_NIDENT = 16;

    // Section header types
    private static final int SHT_NULL = 0;
    private static final int SHT_PROGBITS = 1;
    private static final int SHT_STRTAB = 3;
    private static final int SHT_RELA = 4;
    private static final int SHT_DYNAMIC = 6;
    private static final int SHT_NOBITS = 8;
    private static final int SHT_REL = 9;
    private static final int SHT_DYNSYM = 11;

    // Section header flags
    private static final int SHF_WRITE = 0x1;
    private static final int SHF_ALLOC = 0x2;
    private static final int SHF_EXECINSTR = 0x4;

    public static class ElfHeader {
        public int classBits; // 32 or 64
        public int dataEndian; // 1=LE, 2=BE
        public int type; // ET_EXEC=2, ET_DYN=3
        public int machine; // EM_ARM=40, EM_AARCH64=183, EM_386=3
        public long entryPoint;
        public long phOffset;
        public long shOffset;
        public int phNum;
        public int shNum;
        public int shStrndx;
        public String arch;
        public String typeStr;
    }

    public static class SectionHeader {
        public int nameOffset;
        public String name;
        public int type;
        public long flags;
        public long addr;
        public long offset;
        public long size;
        public int link;
        public int info;
        public long addralign;
        public long entsize;
    }

    public static class SymbolEntry {
        public long offset;
        public String name;
        public int type;
        public int bind;
        public long value;
        public long size;
        public String sectionName;
    }

    public static class ElfInfo {
        public ElfHeader header;
        public List<SectionHeader> sections = new ArrayList<>();
        public List<SymbolEntry> symbols = new ArrayList<>();
        public List<SymbolEntry> dynamicSymbols = new ArrayList<>();
        public Map<Long, String> stringsByOffset = new LinkedHashMap<>();
        public long baseAddr = 0;
    }

    public static ElfInfo parse(String soPath) {
        ElfInfo info = new ElfInfo();
        try (FileInputStream fis = new FileInputStream(soPath)) {
            byte[] allBytes = new byte[(int) fis.available()];
            fis.read(allBytes);
            ByteBuffer buf = ByteBuffer.wrap(allBytes);
            buf.order(ByteOrder.LITTLE_ENDIAN);

            // Verify ELF magic
            byte[] magic = new byte[4];
            buf.get(magic);
            if (magic[0] != ELF_MAGIC[0] || magic[1] != ELF_MAGIC[1] ||
                magic[2] != ELF_MAGIC[2] || magic[3] != ELF_MAGIC[3]) {
                return info;
            }

            ElfHeader hdr = new ElfHeader();
            hdr.classBits = buf.get() & 0xFF;
            hdr.dataEndian = buf.get() & 0xFF;
            if (hdr.dataEndian == 2) buf.order(ByteOrder.BIG_ENDIAN);

            buf.position(16); // skip rest of e_ident
            hdr.type = buf.getShort() & 0xFFFF;
            hdr.machine = buf.getShort() & 0xFFFF;

            if (hdr.classBits == 1) { // 32-bit
                buf.getInt(); // version
                hdr.entryPoint = buf.getInt() & 0xFFFFFFFFL;
                hdr.phOffset = buf.getInt() & 0xFFFFFFFFL;
                hdr.shOffset = buf.getInt() & 0xFFFFFFFFL;
                buf.getInt(); // flags
                buf.getShort(); // e_ehsize
                buf.getShort(); // e_phentsize
                hdr.phNum = buf.getShort() & 0xFFFF;
                buf.getShort(); // e_shentsize
                hdr.shNum = buf.getShort() & 0xFFFF;
                hdr.shStrndx = buf.getShort() & 0xFFFF;
            } else { // 64-bit
                buf.getInt(); // version
                hdr.entryPoint = buf.getLong();
                hdr.phOffset = buf.getLong();
                hdr.shOffset = buf.getLong();
                buf.getInt(); // flags
                buf.getShort(); // e_ehsize
                buf.getShort(); // e_phentsize
                hdr.phNum = buf.getShort() & 0xFFFF;
                buf.getShort(); // e_shentsize
                hdr.shNum = buf.getShort() & 0xFFFF;
                hdr.shStrndx = buf.getShort() & 0xFFFF;
            }

            // Arch strings
            switch (hdr.machine) {
                case 3: hdr.arch = "x86"; break;
                case 40: hdr.arch = "ARM"; break;
                case 47: hdr.arch = "ARM"; break;
                case 62: hdr.arch = "x86_64"; break;
                case 183: hdr.arch = "AArch64"; break;
                default: hdr.arch = "Unknown(" + hdr.machine + ")"; break;
            }
            switch (hdr.type) {
                case 1: hdr.typeStr = "ET_REL"; break;
                case 2: hdr.typeStr = "ET_EXEC"; break;
                case 3: hdr.typeStr = "ET_DYN (PIE)"; break;
                default: hdr.typeStr = "Unknown(" + hdr.type + ")"; break;
            }
            info.header = hdr;

            // Parse section headers
            List<SectionHeader> sects = new ArrayList<>();
            for (int i = 0; i < hdr.shNum; i++) {
                long shOff = hdr.shOffset + (long) i * (hdr.classBits == 1 ? 40 : 64);
                buf.position((int) shOff);
                SectionHeader sh = new SectionHeader();
                sh.nameOffset = buf.getInt();
                if (hdr.classBits == 1) {
                    sh.type = buf.getInt();
                    sh.flags = buf.getInt() & 0xFFFFFFFFL;
                    sh.addr = buf.getInt() & 0xFFFFFFFFL;
                    sh.offset = buf.getInt() & 0xFFFFFFFFL;
                    sh.size = buf.getInt() & 0xFFFFFFFFL;
                    sh.link = buf.getInt();
                    sh.info = buf.getInt();
                    sh.addralign = buf.getInt() & 0xFFFFFFFFL;
                    sh.entsize = buf.getInt() & 0xFFFFFFFFL;
                } else {
                    sh.type = buf.getInt();
                    sh.flags = buf.getLong();
                    sh.addr = buf.getLong();
                    sh.offset = buf.getLong();
                    sh.size = buf.getLong();
                    sh.link = buf.getInt();
                    sh.info = buf.getInt();
                    sh.addralign = buf.getLong();
                    sh.entsize = buf.getLong();
                }
                sects.add(sh);
            }

            // Get section name string table
            if (hdr.shStrndx < sects.size()) {
                SectionHeader strtabSh = sects.get(hdr.shStrndx);
                byte[] strtabData = new byte[(int) strtabSh.size];
                buf.position((int) strtabSh.offset);
                buf.get(strtabData);

                for (SectionHeader sh : sects) {
                    sh.name = readString(strtabData, sh.nameOffset);
                }
            }

            info.sections = sects;

            // Find and parse symbol/string tables
            for (SectionHeader sh : sects) {
                if (sh.type == SHT_STRTAB && sh.name != null && !sh.name.isEmpty()) {
                    byte[] stab = new byte[(int) sh.size];
                    buf.position((int) sh.offset);
                    buf.get(stab);
                    // Store strings by offset
                    int pos = 0;
                    while (pos < stab.length) {
                        String s = readString(stab, pos);
                        if (!s.isEmpty()) {
                            info.stringsByOffset.put(sh.offset + pos, s);
                        }
                        pos += s.length() + 1;
                    }
                }

                if (sh.type == SHT_DYNSYM) {
                    SectionHeader dynstrSh = null;
                    if (sh.link < sects.size()) dynstrSh = sects.get(sh.link);
                    if (dynstrSh != null) {
                        byte[] dynstr = new byte[(int) dynstrSh.size];
                        buf.position((int) dynstrSh.offset);
                        buf.get(dynstr);

                        int entrySize = (int) sh.entsize;
                        if (entrySize == 0) entrySize = hdr.classBits == 1 ? 16 : 24;
                        int count = (int) (sh.size / entrySize);

                        for (int i = 1; i < count; i++) {
                            long symOff = sh.offset + (long) i * entrySize;
                            buf.position((int) symOff);
                            SymbolEntry sym = new SymbolEntry();
                            sym.offset = symOff;
                            if (hdr.classBits == 1) {
                                sym.nameOffset = buf.getInt();
                                sym.value = buf.getInt() & 0xFFFFFFFFL;
                                sym.size = buf.getInt() & 0xFFFFFFFFL;
                                int info = buf.get() & 0xFF;
                                sym.bind = info >> 4;
                                sym.type = info & 0xF;
                                buf.getShort(); // shndx
                            } else {
                                int nameIdx = buf.getInt();
                                sym.nameOffset = nameIdx;
                                int info = buf.get() & 0xFF;
                                sym.bind = info >> 4;
                                sym.type = info & 0xF;
                                buf.get(); // other
                                buf.getShort(); // shndx
                                sym.value = buf.getLong();
                                sym.size = buf.getLong();
                            }
                            sym.name = readString(dynstr, sym.nameOffset & 0x7FFFFFFF);
                            if (sym.name != null && !sym.name.isEmpty()) {
                                info.dynamicSymbols.add(sym);
                            }
                        }
                    }
                }
            }

            // Determine base address from first loadable section
            for (SectionHeader sh : sects) {
                if ((sh.flags & SHF_ALLOC) != 0 && sh.addr > 0) {
                    info.baseAddr = sh.addr;
                    break;
                }
            }

        } catch (Exception e) {
            // Return partial info
        }
        return info;
    }

    private static String readString(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) return "";
        StringBuilder sb = new StringBuilder();
        while (offset < data.length && data[offset] != 0) {
            sb.append((char) (data[offset] & 0xFF));
            offset++;
        }
        return sb.toString();
    }
}
