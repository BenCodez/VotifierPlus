package com.vexsoftware.votifier.net;

/** Bounded, single-line representations for data received over vote connections. */
public final class VoteLogSafety {
	private static final int FIELD_CHARS = 96;
	private static final int MESSAGE_CHARS = 240;

	private VoteLogSafety() {
	}

	public static String field(String value) {
		return singleLine(value, FIELD_CHARS);
	}

	public static String message(String value) {
		return singleLine(value, MESSAGE_CHARS);
	}

	public static String exceptionType(Throwable error) {
		return error == null ? "UnknownError" : error.getClass().getSimpleName();
	}

	private static String singleLine(String value, int limit) {
		if (value == null) {
			return "<none>";
		}
		StringBuilder output = new StringBuilder(Math.min(limit, value.length()));
		for (int offset = 0; offset < value.length();) {
			int codePoint = value.codePointAt(offset);
			int chars = Character.charCount(codePoint);
			if (output.length() + chars > limit) {
				while (output.length() > limit - 3) {
					int last = output.codePointBefore(output.length());
					output.setLength(output.length() - Character.charCount(last));
				}
				return output.append("...").toString();
			}
			int type = Character.getType(codePoint);
			if (Character.isISOControl(codePoint) || type == Character.FORMAT
					|| type == Character.LINE_SEPARATOR || type == Character.PARAGRAPH_SEPARATOR
					|| type == Character.SURROGATE) {
				output.append('?');
			} else {
				output.appendCodePoint(codePoint);
			}
			offset += chars;
		}
		return output.toString();
	}
}
