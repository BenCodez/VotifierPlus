package com.vexsoftware.votifier.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Reads an optional resource from the plugin's packaged archive. */
public final class ZipResourceReader {
	private ZipResourceReader() {
	}

	/**
	 * Returns the contents of the named archive entry, or {@code null} when the
	 * archive or entry is unavailable or unreadable. The archive stream is always
	 * closed before this method returns.
	 */
	public static byte[] read(URL archiveUrl, String entryName) {
		if (archiveUrl == null || entryName == null) {
			return null;
		}

		try (InputStream input = archiveUrl.openStream(); ZipInputStream zip = new ZipInputStream(input)) {
			ZipEntry entry;
			while ((entry = zip.getNextEntry()) != null) {
				if (entryName.equals(entry.getName())) {
					try (ByteArrayOutputStream output = new ByteArrayOutputStream()) {
						zip.transferTo(output);
						return output.toByteArray();
					}
				}
			}
		} catch (IOException | RuntimeException ignored) {
			// Version metadata is optional; a missing or damaged archive should not
			// interfere with plugin startup.
		}
		return null;
	}
}
