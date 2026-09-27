package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

import java.io.ByteArrayOutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import com.vexsoftware.votifier.util.ZipResourceReader;

class ZipResourceReaderTest {
	private static final String VERSION_ENTRY = "votifierplusversion.yml";

	@TempDir
	Path tempDir;

	@Test
	void readsPresentEntry() throws Exception {
		byte[] expected = "buildnumber: 123".getBytes(java.nio.charset.StandardCharsets.UTF_8);

		assertArrayEquals(expected, readArchive(createArchive(VERSION_ENTRY, expected)));
	}

	@Test
	void returnsNullWhenEntryIsAbsent() throws Exception {
		assertNull(readArchive(createArchive("other.yml", new byte[] { 1 })));
	}

	@Test
	void preservesAnEmptyEntry() throws Exception {
		assertEquals(0, readArchive(createArchive(VERSION_ENTRY, new byte[0])).length);
	}

	@Test
	void returnsNullForCorruptArchive() throws Exception {
		Path archive = tempDir.resolve("corrupt.jar");
		Files.write(archive, "this is not a zip archive".getBytes(java.nio.charset.StandardCharsets.UTF_8));

		assertNull(ZipResourceReader.read(archive.toUri().toURL(), VERSION_ENTRY));
	}

	private Path createArchive(String entryName, byte[] contents) throws Exception {
		ByteArrayOutputStream bytes = new ByteArrayOutputStream();
		try (ZipOutputStream zip = new ZipOutputStream(bytes)) {
			zip.putNextEntry(new ZipEntry(entryName));
			zip.write(contents);
			zip.closeEntry();
		}
		Path archive = tempDir.resolve("test-" + System.nanoTime() + ".jar");
		Files.write(archive, bytes.toByteArray());
		return archive;
	}

	private byte[] readArchive(Path archive) throws Exception {
		return ZipResourceReader.read(archive.toUri().toURL(), VERSION_ENTRY);
	}
}
