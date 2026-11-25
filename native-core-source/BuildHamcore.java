// Host resource packer following official FileIO.c BuildHamcore/InitHamcore format.
// Apache-2.0. Requires JDK 21; does not execute the target ARM64 binaries.
import java.io.*;
import java.nio.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

class BuildHamcore {
    record Entry(String name, byte[] nameBytes, byte[] original, byte[] compressed, int offset) {}
    public static void main(String[] args) throws Exception {
        Path source = Path.of(args[0]).toAbsolutePath();
        Path output = Path.of(args[1]).toAbsolutePath();
        List<Path> paths;
        try (var stream = Files.walk(source)) {
            paths = stream.filter(Files::isRegularFile).filter(path -> {
                String name = path.toString().toLowerCase(Locale.ROOT);
                return !name.contains("node_modules") && !name.matches(".*\\.(exe|dll|sys|inf|cat|wav)$");
            }).sorted(Comparator.comparing(path -> source.relativize(path).toString(), String.CASE_INSENSITIVE_ORDER)).toList();
        }
        List<Entry> entries = new ArrayList<>();
        int offset = 11;
        for (Path path : paths) {
            String name = source.relativize(path).toString().replace('/', '\\');
            byte[] nameBytes = name.getBytes(StandardCharsets.UTF_8);
            byte[] original = Files.readAllBytes(path);
            var compressed = new ByteArrayOutputStream();
            try (var deflater = new DeflaterOutputStream(compressed)) { deflater.write(original); }
            entries.add(new Entry(name, nameBytes, original, compressed.toByteArray(), 0));
            offset = Math.addExact(offset, nameBytes.length + 16);
        }
        for (int i = 0; i < entries.size(); i++) {
            Entry entry = entries.get(i);
            entries.set(i, new Entry(entry.name, entry.nameBytes, entry.original, entry.compressed, offset));
            offset = Math.addExact(offset, entry.compressed.length);
        }
        Files.createDirectories(output.getParent());
        try (var target = new DataOutputStream(new BufferedOutputStream(Files.newOutputStream(output)))) {
            target.write("HamCore".getBytes(StandardCharsets.US_ASCII));
            target.writeInt(entries.size());
            for (Entry entry : entries) {
                target.writeInt(entry.nameBytes.length + 1); target.write(entry.nameBytes);
                target.writeInt(entry.original.length); target.writeInt(entry.compressed.length); target.writeInt(entry.offset);
            }
            for (Entry entry : entries) target.write(entry.compressed);
        }
        // Independent read-back of every table offset and zlib payload against source bytes.
        byte[] archive = Files.readAllBytes(output);
        var reader = ByteBuffer.wrap(archive).order(ByteOrder.BIG_ENDIAN);
        byte[] magic = new byte[7]; reader.get(magic);
        if (!Arrays.equals(magic, "HamCore".getBytes(StandardCharsets.US_ASCII)) || reader.getInt() != entries.size()) throw new IOException("Bad HamCore header");
        for (Entry expected : entries) {
            int length = reader.getInt() - 1;
            byte[] name = new byte[length]; reader.get(name);
            int size = reader.getInt(), compressed = reader.getInt(), position = reader.getInt();
            byte[] restored;
            try (var inflater = new InflaterInputStream(new ByteArrayInputStream(archive, position, compressed))) { restored = inflater.readAllBytes(); }
            if (!Arrays.equals(name, expected.nameBytes) || size != expected.original.length || !Arrays.equals(restored, expected.original)) throw new IOException("HamCore verification failed: " + expected.name);
        }
        System.out.println("HamCore: " + entries.size() + " entries; " + archive.length + " bytes; all payloads verified.");
    }
}
