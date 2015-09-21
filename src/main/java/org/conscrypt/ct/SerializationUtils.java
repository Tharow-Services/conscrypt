/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.conscrypt.ct;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Vector;

public class SerializationUtils {
    private SerializationUtils() {}

    public static byte[] readDEROctetString(byte[] input)
            throws SerializationException {
        return readDEROctetString(new ByteArrayInputStream(input));
    }

    public static byte[] readDEROctetString(InputStream input)
            throws SerializationException {
        byte tag = readByte(input);
        if ((tag & 0xbf) != 0x4) {
            throw new SerializationException("Wrong DER tag.");
        }
        int length;
        int width = readNumber(input, 1);
        if (width >= 0x80) {
            length = readNumber(input, width - 0x80);
        } else {
            length = width;
        }

        return readFixedBytes(input, length);
    }

    public static byte[][] readList(byte[] input, int listWidth, int elemWidth)
            throws SerializationException {
        return readList(new ByteArrayInputStream(input), listWidth, elemWidth);
    }

    /**
     * Read a variable length vector of variable sized elements as described by RFC5246 section 4.3.
     * The vector is prefixed by it's total length, in bytes and in big endian format,
     * so is each element contained in the vector.
     * @param listWidth the width of the vector's length field, in bytes.
     * @param elemWidth the width of each element's length field, in bytes.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte[][] readList(InputStream input, int listWidth, int elemWidth)
            throws SerializationException {
        Vector<byte[]> result = new Vector();
        byte[] data = readVariableBytes(input, listWidth);
        input = new ByteArrayInputStream(data);
        try {
            while (input.available() > 0) {
                result.add(readVariableBytes(input, elemWidth));
            }
        } catch (IOException e) {
            throw new SerializationException(e);
        }
        return result.toArray(new byte[result.size()][]);
    }

    /**
     * Read a length-prefixed sequence of bytes.
     * The length must be encoded in big endian format.
     * @param width the width of the length prefix, in bytes.
     * @throws SerializationException if EOF is encountered, or if {@code width} is negative or
     * greater than 4
     */
    public static byte[] readVariableBytes(InputStream input, int width)
            throws SerializationException {
        int length = readNumber(input, width);
        return readFixedBytes(input, length);
    }

    /**
     * Read a fixed number of bytes from the input stream.
     * @param length the number of bytes to read.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte[] readFixedBytes(InputStream input, int length)
            throws SerializationException {
        try {
            if (length < 0) {
                throw new SerializationException("Length cannot be negative");
            }

            byte[] data = new byte[length];
            if (input.read(data) < length) {
                throw new SerializationException("Premature end of input.");
            }
            return data;
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Read a number in big endian format from the input stream.
     * This methods only supports a width of up to 4 bytes.
     * @param width the width of the number, in bytes.
     * @throws SerializationException if EOF is encountered, or if {@code width} is negative or
     * greater than 4
     */
    public static int readNumber(InputStream input, int width) throws SerializationException {
        if (width > 4 || width < 0) {
            throw new SerializationException("Invalid width");
        }

        int result = 0;
        for (int i = 0; i < width; i++) {
            result = (result << 8) | (readByte(input) & 0xFF);
        }

        return result;
    }

    /**
     * Read a number in big endian format from the input stream.
     * This methods supports a width of up to 8 bytes.
     * @param width the width of the number, in bytes.
     * @throws SerializationException if EOF is encountered.
     * @throws IllegalArgumentException if {@code width} is negative or greater than 8
     */
    public static long readLong(InputStream input, int width) throws SerializationException {
        if (width > 8 || width < 0) {
            throw new IllegalArgumentException("Invalid width");
        }

        long result = 0;
        for (int i = 0; i < width; i++) {
            result = (result << 8) | (readByte(input) & 0xFF);
        }

        return result;
    }

    /**
     * Read a single byte from the input stream.
     * @throws SerializationException if EOF is encountered.
     */
    public static byte readByte(InputStream input) throws SerializationException {
        try {
            int b = input.read();
            if (b == -1) {
                throw new SerializationException("Premature end of input.");
            }
            return (byte)b;
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Write length prefixed sequence of bytes to the ouput stream.
     * The length prefix is encoded in big endian order.
     * @param data the data to be written.
     * @param width the width of the length prefix, in bytes.
     * @throws SerializationException if the length of {@code data} is too large to fit in
     * {@code width} bytes.
     */
    public static void writeVariableBytes(OutputStream output, byte[] data, int width)
            throws SerializationException {
        writeNumber(output, data.length, width);
        writeFixedBytes(output, data);
    }

    /**
     * Write a fixed number sequence of bytes to the ouput stream.
     * @param data the data to be written.
     */
    public static void writeFixedBytes(OutputStream output, byte[] data)
            throws SerializationException {
        try {
            output.write(data);
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }

    /**
     * Write a number to the output stream.
     * The number is encoded in big endian order.
     * @param value the value to be written.
     * @param width the width of the encoded number, in bytes
     * @throws SerializationException if the number is too large to fit in {@code width} bytes.
     */
    public static void writeNumber(OutputStream output, long value, int width)
            throws SerializationException {
        if (width < 0) {
            throw new IllegalArgumentException("Width cannot be negative.");
        }
        if (width < 8 && value >= (1L << (8*width))) {
            throw new SerializationException("Number too large.");
        }

        try {
            while (width > 0) {
                long shift = (width - 1) * 8;
                if (shift < 64) {
                    output.write((byte)((value >> shift) & 0xFF));
                } else {
                    output.write(0);
                }

                width --;
            }
        } catch (IOException e) {
            throw new SerializationException(e);
        }
    }
}

