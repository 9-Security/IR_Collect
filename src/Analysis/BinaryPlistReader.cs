using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;

namespace IR_Collect.Analysis
{
    /// <summary>
    /// Bounded Apple binary property-list reader for structured UAC intake.
    /// It supports the bplist00 scalar, array, set, and dictionary object types.
    /// </summary>
    internal static class BinaryPlistReader
    {
        private const long MaxFileBytes = 20L * 1024 * 1024;
        private const ulong MaxObjects = 1000000;
        private const ulong MaxCollectionItems = 100000;
        private const ulong MaxScalarBytes = 16UL * 1024 * 1024;
        private const int MaxDepth = 64;

        public static bool HasSignature(string path)
        {
            try
            {
                using (FileStream stream = File.OpenRead(path))
                {
                    if (stream.Length < 8) return false;
                    byte[] signature = new byte[8];
                    return stream.Read(signature, 0, signature.Length) == signature.Length &&
                        string.Equals(Encoding.ASCII.GetString(signature), "bplist00", StringComparison.Ordinal);
                }
            }
            catch { return false; }
        }

        public static bool TryReadDictionary(string path, out Dictionary<string, object> dictionary, out string error)
        {
            dictionary = null;
            error = "";
            try
            {
                if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                    throw new InvalidDataException("Binary plist file was not found.");
                FileInfo info = new FileInfo(path);
                if (info.Length < 40 || info.Length > MaxFileBytes)
                    throw new InvalidDataException("Binary plist size is outside the supported bounds.");
                var parser = new Parser(File.ReadAllBytes(path));
                object root = parser.Parse();
                dictionary = root as Dictionary<string, object>;
                if (dictionary == null)
                    throw new InvalidDataException("Binary plist root object is not a dictionary.");
                return true;
            }
            catch (Exception ex)
            {
                error = ex.Message ?? "Binary plist parse failed.";
                dictionary = null;
                return false;
            }
        }

        private sealed class Parser
        {
            private readonly byte[] _data;
            private readonly Dictionary<ulong, object> _cache;
            private readonly HashSet<ulong> _active;
            private int _offsetIntegerSize;
            private int _objectReferenceSize;
            private ulong _numberOfObjects;
            private ulong _topObject;
            private ulong _offsetTableOffset;
            private ulong[] _objectOffsets;

            public Parser(byte[] data)
            {
                _data = data ?? new byte[0];
                _cache = new Dictionary<ulong, object>();
                _active = new HashSet<ulong>();
            }

            public object Parse()
            {
                if (_data.Length < 40 ||
                    !string.Equals(Encoding.ASCII.GetString(_data, 0, 8), "bplist00", StringComparison.Ordinal))
                    throw new InvalidDataException("Invalid binary plist signature.");

                int trailer = _data.Length - 32;
                _offsetIntegerSize = _data[trailer + 6];
                _objectReferenceSize = _data[trailer + 7];
                _numberOfObjects = ReadUnsignedBigEndian(trailer + 8, 8);
                _topObject = ReadUnsignedBigEndian(trailer + 16, 8);
                _offsetTableOffset = ReadUnsignedBigEndian(trailer + 24, 8);

                if (_offsetIntegerSize < 1 || _offsetIntegerSize > 8 ||
                    _objectReferenceSize < 1 || _objectReferenceSize > 8)
                    throw new InvalidDataException("Invalid binary plist integer sizes.");
                if (_numberOfObjects == 0 || _numberOfObjects > MaxObjects || _topObject >= _numberOfObjects)
                    throw new InvalidDataException("Invalid binary plist object table.");
                if (_offsetTableOffset < 8 || _offsetTableOffset >= (ulong)trailer)
                    throw new InvalidDataException("Invalid binary plist offset table location.");
                if (_numberOfObjects > ((ulong)trailer - _offsetTableOffset) / (ulong)_offsetIntegerSize)
                    throw new InvalidDataException("Binary plist offset table is truncated.");

                _objectOffsets = new ulong[(int)_numberOfObjects];
                for (ulong i = 0; i < _numberOfObjects; i++)
                {
                    ulong location = _offsetTableOffset + i * (ulong)_offsetIntegerSize;
                    ulong offset = ReadUnsignedBigEndian(ToInt(location), _offsetIntegerSize);
                    if (offset < 8 || offset >= _offsetTableOffset)
                        throw new InvalidDataException("Binary plist object offset is outside the object table.");
                    _objectOffsets[(int)i] = offset;
                }

                return ParseObject(_topObject, 0);
            }

            private object ParseObject(ulong objectIndex, int depth)
            {
                if (depth > MaxDepth) throw new InvalidDataException("Binary plist nesting limit exceeded.");
                if (objectIndex >= _numberOfObjects) throw new InvalidDataException("Binary plist reference is out of range.");

                object cached;
                if (_cache.TryGetValue(objectIndex, out cached)) return cached;
                if (!_active.Add(objectIndex)) throw new InvalidDataException("Binary plist contains a cyclic reference.");
                try
                {
                    int offset = ToInt(_objectOffsets[(int)objectIndex]);
                    byte marker = _data[offset];
                    int type = marker >> 4;
                    int info = marker & 0x0F;
                    object value;
                    switch (type)
                    {
                        case 0x0:
                            value = ParseSimple(info);
                            break;
                        case 0x1:
                            value = ParseInteger(offset, info);
                            break;
                        case 0x2:
                            value = ParseReal(offset, info);
                            break;
                        case 0x3:
                            value = ParseDate(offset, info);
                            break;
                        case 0x4:
                            value = ParseData(offset, info);
                            break;
                        case 0x5:
                            value = ParseAsciiString(offset, info);
                            break;
                        case 0x6:
                            value = ParseUtf16String(offset, info);
                            break;
                        case 0x7:
                            value = ParseUtf8String(offset, info);
                            break;
                        case 0x8:
                            value = ParseUid(offset, info);
                            break;
                        case 0xA:
                        case 0xB:
                        case 0xC:
                            value = ParseCollection(offset, info, depth);
                            break;
                        case 0xD:
                            value = ParseDictionary(offset, info, depth);
                            break;
                        default:
                            throw new InvalidDataException("Unsupported binary plist object marker.");
                    }
                    _cache[objectIndex] = value;
                    return value;
                }
                finally
                {
                    _active.Remove(objectIndex);
                }
            }

            private static object ParseSimple(int info)
            {
                if (info == 0x0) return null;
                if (info == 0x8) return false;
                if (info == 0x9) return true;
                if (info == 0xF) return null;
                throw new InvalidDataException("Unsupported binary plist simple value.");
            }

            private object ParseInteger(int offset, int info)
            {
                int byteCount = PowerOfTwoByteCount(info);
                EnsureObjectRange(offset + 1, byteCount);
                if (byteCount > 8)
                    return "0x" + ToHex(_data, offset + 1, byteCount);

                ulong unsignedValue = ReadUnsignedBigEndian(offset + 1, byteCount);
                if (byteCount == 8) return unchecked((long)unsignedValue);
                ulong signBit = 1UL << (byteCount * 8 - 1);
                if ((unsignedValue & signBit) == 0) return (long)unsignedValue;
                ulong modulus = 1UL << (byteCount * 8);
                return unchecked((long)(unsignedValue - modulus));
            }

            private object ParseReal(int offset, int info)
            {
                int byteCount = PowerOfTwoByteCount(info);
                EnsureObjectRange(offset + 1, byteCount);
                if (byteCount == 4)
                {
                    byte[] bytes = CopyBigEndianForBitConverter(offset + 1, 4);
                    return (double)BitConverter.ToSingle(bytes, 0);
                }
                if (byteCount == 8)
                {
                    byte[] bytes = CopyBigEndianForBitConverter(offset + 1, 8);
                    return BitConverter.ToDouble(bytes, 0);
                }
                throw new InvalidDataException("Unsupported binary plist real size.");
            }

            private object ParseDate(int offset, int info)
            {
                if (info != 3) throw new InvalidDataException("Invalid binary plist date marker.");
                byte[] bytes = CopyBigEndianForBitConverter(offset + 1, 8);
                double seconds = BitConverter.ToDouble(bytes, 0);
                if (double.IsNaN(seconds) || double.IsInfinity(seconds))
                    throw new InvalidDataException("Invalid binary plist date value.");
                try
                {
                    return new DateTime(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(seconds);
                }
                catch { throw new InvalidDataException("Binary plist date is outside the supported range."); }
            }

            private object ParseData(int offset, int info)
            {
                ulong length;
                int payloadOffset;
                ReadLength(offset, info, out length, out payloadOffset);
                if (length > MaxScalarBytes) throw new InvalidDataException("Binary plist data value is too large.");
                int count = ToInt(length);
                EnsureObjectRange(payloadOffset, count);
                byte[] value = new byte[count];
                Buffer.BlockCopy(_data, payloadOffset, value, 0, count);
                return value;
            }

            private object ParseAsciiString(int offset, int info)
            {
                ulong length;
                int payloadOffset;
                ReadLength(offset, info, out length, out payloadOffset);
                if (length > MaxScalarBytes) throw new InvalidDataException("Binary plist ASCII string is too large.");
                int count = ToInt(length);
                EnsureObjectRange(payloadOffset, count);
                return Encoding.ASCII.GetString(_data, payloadOffset, count);
            }

            private object ParseUtf8String(int offset, int info)
            {
                ulong length;
                int payloadOffset;
                ReadLength(offset, info, out length, out payloadOffset);
                if (length > MaxScalarBytes) throw new InvalidDataException("Binary plist UTF-8 string is too large.");
                int count = ToInt(length);
                EnsureObjectRange(payloadOffset, count);
                return new UTF8Encoding(false, true).GetString(_data, payloadOffset, count);
            }

            private object ParseUtf16String(int offset, int info)
            {
                ulong characterCount;
                int payloadOffset;
                ReadLength(offset, info, out characterCount, out payloadOffset);
                if (characterCount > MaxScalarBytes / 2) throw new InvalidDataException("Binary plist UTF-16 string is too large.");
                int byteCount = ToInt(characterCount * 2);
                EnsureObjectRange(payloadOffset, byteCount);
                return Encoding.BigEndianUnicode.GetString(_data, payloadOffset, byteCount);
            }

            private object ParseUid(int offset, int info)
            {
                int byteCount = info + 1;
                if (byteCount > 8) throw new InvalidDataException("Binary plist UID is too large.");
                EnsureObjectRange(offset + 1, byteCount);
                return new PlistUid(ReadUnsignedBigEndian(offset + 1, byteCount));
            }

            private object ParseCollection(int offset, int info, int depth)
            {
                ulong count;
                int referencesOffset;
                ReadLength(offset, info, out count, out referencesOffset);
                if (count > MaxCollectionItems) throw new InvalidDataException("Binary plist collection is too large.");
                EnsureReferenceRange(referencesOffset, count);
                var values = new List<object>((int)count);
                for (ulong i = 0; i < count; i++)
                {
                    ulong reference = ReadUnsignedBigEndian(
                        referencesOffset + ToInt(i * (ulong)_objectReferenceSize),
                        _objectReferenceSize);
                    values.Add(ParseObject(reference, depth + 1));
                }
                return values;
            }

            private object ParseDictionary(int offset, int info, int depth)
            {
                ulong count;
                int referencesOffset;
                ReadLength(offset, info, out count, out referencesOffset);
                if (count > MaxCollectionItems) throw new InvalidDataException("Binary plist dictionary is too large.");
                if (count > (ulong)int.MaxValue / 2) throw new InvalidDataException("Binary plist dictionary reference count is too large.");
                EnsureReferenceRange(referencesOffset, count * 2);
                int valueReferencesOffset = referencesOffset + ToInt(count * (ulong)_objectReferenceSize);
                var values = new Dictionary<string, object>(StringComparer.Ordinal);
                for (ulong i = 0; i < count; i++)
                {
                    ulong keyReference = ReadUnsignedBigEndian(
                        referencesOffset + ToInt(i * (ulong)_objectReferenceSize),
                        _objectReferenceSize);
                    ulong valueReference = ReadUnsignedBigEndian(
                        valueReferencesOffset + ToInt(i * (ulong)_objectReferenceSize),
                        _objectReferenceSize);
                    object keyObject = ParseObject(keyReference, depth + 1);
                    string key = keyObject as string;
                    if (key == null) throw new InvalidDataException("Binary plist dictionary key is not a string.");
                    values[key] = ParseObject(valueReference, depth + 1);
                }
                return values;
            }

            private void ReadLength(int objectOffset, int info, out ulong length, out int payloadOffset)
            {
                if (info < 0xF)
                {
                    length = (ulong)info;
                    payloadOffset = objectOffset + 1;
                    return;
                }

                int integerOffset = objectOffset + 1;
                EnsureObjectRange(integerOffset, 1);
                byte marker = _data[integerOffset];
                if ((marker >> 4) != 0x1)
                    throw new InvalidDataException("Binary plist extended length is not an integer.");
                int byteCount = PowerOfTwoByteCount(marker & 0x0F);
                if (byteCount > 8) throw new InvalidDataException("Binary plist extended length is too large.");
                EnsureObjectRange(integerOffset + 1, byteCount);
                length = ReadUnsignedBigEndian(integerOffset + 1, byteCount);
                payloadOffset = integerOffset + 1 + byteCount;
            }

            private void EnsureReferenceRange(int offset, ulong count)
            {
                if (count > (ulong)int.MaxValue / (ulong)_objectReferenceSize)
                    throw new InvalidDataException("Binary plist reference array is too large.");
                EnsureObjectRange(offset, ToInt(count * (ulong)_objectReferenceSize));
            }

            private static int PowerOfTwoByteCount(int exponent)
            {
                if (exponent < 0 || exponent > 4)
                    throw new InvalidDataException("Binary plist integer exponent is outside the supported range.");
                return 1 << exponent;
            }

            private ulong ReadUnsignedBigEndian(int offset, int byteCount)
            {
                if (byteCount < 1 || byteCount > 8)
                    throw new InvalidDataException("Invalid binary plist integer width.");
                EnsureRange(offset, byteCount);
                ulong value = 0;
                for (int i = 0; i < byteCount; i++)
                    value = (value << 8) | _data[offset + i];
                return value;
            }

            private byte[] CopyBigEndianForBitConverter(int offset, int byteCount)
            {
                EnsureObjectRange(offset, byteCount);
                byte[] bytes = new byte[byteCount];
                Buffer.BlockCopy(_data, offset, bytes, 0, byteCount);
                if (BitConverter.IsLittleEndian) Array.Reverse(bytes);
                return bytes;
            }

            private void EnsureRange(int offset, int count)
            {
                if (offset < 0 || count < 0 || offset > _data.Length - count)
                    throw new InvalidDataException("Binary plist object is truncated.");
            }

            private void EnsureObjectRange(int offset, int count)
            {
                EnsureRange(offset, count);
                if ((ulong)offset > _offsetTableOffset ||
                    (ulong)count > _offsetTableOffset - (ulong)offset)
                    throw new InvalidDataException("Binary plist object overlaps the offset table.");
            }

            private static int ToInt(ulong value)
            {
                if (value > int.MaxValue) throw new InvalidDataException("Binary plist offset exceeds the supported range.");
                return (int)value;
            }

            private static string ToHex(byte[] bytes, int offset, int count)
            {
                var sb = new StringBuilder(count * 2);
                for (int i = 0; i < count; i++)
                    sb.Append(bytes[offset + i].ToString("x2", CultureInfo.InvariantCulture));
                return sb.ToString();
            }
        }

        private sealed class PlistUid
        {
            private readonly ulong _value;

            public PlistUid(ulong value)
            {
                _value = value;
            }

            public override string ToString()
            {
                return _value.ToString(CultureInfo.InvariantCulture);
            }
        }
    }
}
