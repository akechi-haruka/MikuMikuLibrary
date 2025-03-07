using System.IO.Compression;
using System.Security.Cryptography;
using MikuMikuLibrary.IO;
using MikuMikuLibrary.IO.Common;
using MikuMikuLibrary.IO.Sections;
using ZstdNet;

namespace MikuMikuLibrary.Archives;

public class FarcArchive : BinaryFile, IArchive {
    private readonly Dictionary<string, Entry> mEntries = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
    private int mAlignment = 0x10;

    public int Alignment {
        get { return mAlignment; }
        set { mAlignment = (value & (value - 1)) != 0 ? AlignmentHelper.AlignToNextPowerOfTwo(value) : value; }
    }

    public bool IsCompressed { get; set; }

    public override BinaryFileFlags Flags {
        get { return BinaryFileFlags.Load | BinaryFileFlags.Save | BinaryFileFlags.UsesSourceStream; }
    }

    public override Endianness Endianness {
        get { return Endianness.Big; }
    }

    public bool CanAdd {
        get { return true; }
    }

    public bool CanRemove {
        get { return true; }
    }

    public IEnumerable<string> FileNames {
        get { return mEntries.Keys; }
    }

    public void Add(string fileName, Stream source, bool leaveOpen, ConflictPolicy conflictPolicy = ConflictPolicy.RaiseError) {
        if (mEntries.TryGetValue(fileName, out Entry entry)) {
            switch (conflictPolicy) {
                case ConflictPolicy.RaiseError:
                    throw new InvalidOperationException($"Entry already exists ({fileName})");

                case ConflictPolicy.Replace:
                    if (source is EntryStream entryStream && entryStream.Source == source) {
                        break;
                    }

                    entry.Dispose();
                    entry.Stream = source;
                    entry.OwnsStream = !leaveOpen;
                    break;

                case ConflictPolicy.Ignore:
                    break;
            }
        } else {
            mEntries.Add(fileName, new Entry {
                Name = fileName,
                Stream = source,
                OwnsStream = !leaveOpen
            });
        }
    }

    public void Add(string fileName, string sourceFilePath, ConflictPolicy conflictPolicy = ConflictPolicy.RaiseError) {
        Add(fileName, File.OpenRead(sourceFilePath), false, conflictPolicy);
    }

    public void Remove(string fileName) {
        if (!mEntries.TryGetValue(fileName, out Entry entry)) {
            return;
        }

        entry.Dispose();
        mEntries.Remove(fileName);
    }

    public EntryStream Open(string fileName, EntryStreamMode mode) {
        Entry entry = mEntries[fileName];
        Stream entryStream = entry.Open(mStream);

        if (mode != EntryStreamMode.MemoryStream) {
            return new EntryStream(entry.Name, entryStream);
        }

        Stream temp = entryStream;
        entryStream = new MemoryStream();
        temp.CopyTo(entryStream);
        entryStream.Position = 0;
        temp.Close();

        return new EntryStream(entry.Name, entryStream);
    }

    public void Clear() {
        foreach (Entry entry in mEntries.Values) {
            entry.Dispose();
        }

        mEntries.Clear();
    }

    public bool Contains(string fileName) {
        return mEntries.ContainsKey(fileName);
    }

    public IEnumerator<string> GetEnumerator() {
        return mEntries.Keys.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator() {
        return mEntries.Keys.GetEnumerator();
    }

    public override void Read(EndianBinaryReader reader, ISection section = null) {
        string signature = reader.ReadString(StringBinaryFormat.FixedLength, 4);
        if (signature != "FARC" && signature != "FArC" && signature != "FArc" && signature != "FARc") {
            throw new InvalidDataException("Invalid signature (expected FARC/FArC/FArc/FARc)");
        }

        uint headerSize = reader.ReadUInt32() + 0x08;
        Stream originalStream = reader.BaseStream;

        if (signature == "FARC") {
            int flags = reader.ReadInt32();
            bool isCompressed = (flags & 2) != 0;
            bool isEncrypted = (flags & 4) != 0;
            reader.ReadInt32(); // padding
            mAlignment = reader.ReadInt32();

            IsCompressed = isCompressed;

            // Hacky way of checking Future Tone.
            // There's a very low chance this isn't going to work, though.
            Format = isEncrypted && (mAlignment & (mAlignment - 1)) != 0 ? BinaryFormat.FT : BinaryFormat.DT;

            if (Format == BinaryFormat.FT) {
                reader.SeekBegin(0x10);
                byte[] iv = reader.ReadBytes(0x10);
                Aes aesManaged = CreateAesForFt(iv);
                ICryptoTransform decryptor = aesManaged.CreateDecryptor();
                CryptoStream cryptoStream = new CryptoStream(reader.BaseStream, decryptor, CryptoStreamMode.Read);
                reader = new EndianBinaryReader(cryptoStream, Encoding.UTF8, Endianness.Big);
                mAlignment = reader.ReadInt32();
            }

            Format = reader.ReadInt32() == 1 ? BinaryFormat.FT : BinaryFormat.DT;

            int entryCount = reader.ReadInt32();
            if (Format == BinaryFormat.FT) {
                reader.ReadInt32(); // padding, No SeekCurrent!! CryptoStream does not support it.
            }

            while (originalStream.Position < headerSize) {
                string name = reader.ReadString(StringBinaryFormat.NullTerminated);
                uint offset = reader.ReadUInt32();
                uint compressedSize = reader.ReadUInt32();
                uint uncompressedSize = reader.ReadUInt32();

                if (Format == BinaryFormat.FT) {
                    flags = reader.ReadInt32();
                    isCompressed = (flags & 2) != 0;
                    isEncrypted = (flags & 4) != 0;
                }

                long fixedSize;

                if (isEncrypted) {
                    fixedSize = AlignmentHelper.Align(isCompressed ? compressedSize : uncompressedSize, 16);
                } else if (isCompressed) {
                    fixedSize = compressedSize;
                } else {
                    fixedSize = uncompressedSize;
                }

                fixedSize = Math.Min(fixedSize, originalStream.Length - offset);

                mEntries.Add(name, new Entry {
                    Name = name,
                    Position = offset,
                    UnpackedLength = uncompressedSize,
                    CompressedLength = Math.Min(compressedSize, originalStream.Length - offset),
                    Length = fixedSize,
                    IsGzipCompressed = isCompressed && compressedSize != uncompressedSize,
                    IsEncrypted = isEncrypted,
                    IsFutureTone = Format == BinaryFormat.FT
                });

                // There's sometimes extra padding on some FARC files which
                // causes this loop to throw an exception. This check fixes it.
                if (Format == BinaryFormat.FT && --entryCount == 0) {
                    break;
                }
            }
        } else if (signature == "FArC") {
            mAlignment = reader.ReadInt32();

            while (reader.Position < headerSize) {
                string name = reader.ReadString(StringBinaryFormat.NullTerminated);
                uint offset = reader.ReadUInt32();
                uint compressedSize = reader.ReadUInt32();
                uint uncompressedSize = reader.ReadUInt32();

                long fixedSize = Math.Min(compressedSize, reader.Length - offset);

                mEntries.Add(name, new Entry {
                    Name = name,
                    Position = offset,
                    UnpackedLength = uncompressedSize,
                    CompressedLength = fixedSize,
                    Length = fixedSize,
                    IsGzipCompressed = compressedSize != uncompressedSize
                });
            }

            IsCompressed = true;
        } else if (signature == "FARc") {
            int flags = reader.ReadInt32();
            bool isGzipCompressed = (flags & 2) != 0;
            bool isEncrypted = (flags & 4) != 0;
            bool isZstdCompressed = false;
            reader.ReadInt32(); // padding
            mAlignment = reader.ReadInt32();

            IsCompressed = isGzipCompressed;

            Format = BinaryFormat.FGO;

            if (isEncrypted) {
                reader.SeekBegin(0x10);
                byte[] iv = reader.ReadBytes(0x10);
                Aes aesManaged = CreateAesForFgo(iv);
                ICryptoTransform decryptor = aesManaged.CreateDecryptor();
                CryptoStream cryptoStream = new CryptoStream(reader.BaseStream, decryptor, CryptoStreamMode.Read);
                reader = new EndianBinaryReader(cryptoStream, Encoding.UTF8, Endianness.Big);
                mAlignment = reader.ReadInt32();
            }

            int formatSpecifier = reader.ReadInt32();
            if (formatSpecifier == 4) {
                Format = BinaryFormat.FGO2;
            } else if (formatSpecifier == 1) {
                Format = BinaryFormat.FGO;
            } else {
                Format = BinaryFormat.DT;
            }

            int entryCount = reader.ReadInt32();
            if (Format == BinaryFormat.FGO || Format == BinaryFormat.FGO2) {
                reader.ReadInt32(); // padding, No SeekCurrent!! CryptoStream does not support it.
            }

            while (originalStream.Position < headerSize) {
                string name = reader.ReadString(StringBinaryFormat.NullTerminated);
                uint offset = reader.ReadUInt32();
                uint compressedSize = reader.ReadUInt32();
                uint uncompressedSize = reader.ReadUInt32();

                if (Format == BinaryFormat.FGO || Format == BinaryFormat.FGO2) {
                    flags = reader.ReadInt32();
                    isGzipCompressed = (flags & 2) != 0;
                    isZstdCompressed = (flags & 32) != 0;
                    isEncrypted = (flags & 4) != 0;
                }

                if (Format == BinaryFormat.FGO2) {
                    // HACK: there's some weird unknown data of variable length before the data so... uhhh.....
                    // this does work ... for now...
                    long pos = reader.Position;
                    reader.SeekBegin(offset);
                    for (uint read = 0; read < 1024; read += 4) {
                        uint unknown = reader.ReadUInt32();
                        if (unknown % 0x100 != 0) {
                            offset += read;
                            break;
                        }
                    }

                    reader.SeekBegin(pos);
                }

                long fixedSize;

                if (isEncrypted) {
                    fixedSize = AlignmentHelper.Align(isGzipCompressed ? compressedSize : uncompressedSize, 16);
                } else if (isGzipCompressed || isZstdCompressed) {
                    fixedSize = compressedSize;
                } else {
                    fixedSize = uncompressedSize;
                }

                fixedSize = Math.Min(fixedSize, originalStream.Length - offset);

                mEntries.Add(name, new Entry {
                    Name = name,
                    Position = offset,
                    UnpackedLength = uncompressedSize,
                    CompressedLength = Math.Min(compressedSize, originalStream.Length - offset),
                    Length = fixedSize,
                    IsGzipCompressed = isGzipCompressed && compressedSize != uncompressedSize,
                    IsZstdCompressed = isZstdCompressed && compressedSize != uncompressedSize,
                    IsEncrypted = isEncrypted,
                    IsFate = Format == BinaryFormat.FGO || Format == BinaryFormat.FGO2
                });

                // There's sometimes extra padding on some FARC files which
                // causes this loop to throw an exception. This check fixes it.
                if (Format == BinaryFormat.FGO && --entryCount == 0) {
                    break;
                }
            }
        } else if (signature == "FArc") {
            mAlignment = reader.ReadInt32();

            while (reader.Position < headerSize) {
                string name = reader.ReadString(StringBinaryFormat.NullTerminated);
                uint offset = reader.ReadUInt32();
                uint size = reader.ReadUInt32();

                long fixedSize = Math.Min(size, reader.Length - offset);

                mEntries.Add(name, new Entry {
                    Name = name,
                    Position = offset,
                    UnpackedLength = fixedSize,
                    Length = fixedSize
                });
            }

            IsCompressed = false;
        }
    }

    public override void Write(EndianBinaryWriter writer, ISection section = null) {
        writer.Write(IsCompressed ? "FArC" : "FArc", StringBinaryFormat.FixedLength, 4);
        writer.WriteOffset(OffsetMode.Size, () => {
            writer.Write(mAlignment);

            foreach (Entry entry in mEntries.Values.OrderBy(x => x.Name)) {
                writer.Write(entry.Name, StringBinaryFormat.NullTerminated);
                writer.WriteOffset(OffsetMode.OffsetAndSize, () => {
                    writer.Align(mAlignment, 0x78);

                    long position = writer.Position;

                    entry.CopyTo(writer.BaseStream, mStream, IsCompressed);

                    entry.Position = position;
                    entry.Length = writer.Position - position;

                    entry.IsGzipCompressed = IsCompressed;

                    if (IsCompressed) {
                        entry.CompressedLength = entry.Length;
                    } else {
                        entry.CompressedLength = -1;
                        entry.UnpackedLength = entry.Length;
                    }

                    entry.IsEncrypted = false;
                    entry.IsFutureTone = false;

                    if (entry.Stream != null) {
                        entry.UnpackedLength = entry.Stream.Length;

                        if (entry.OwnsStream) {
                            entry.Stream.Dispose();
                        }

                        entry.Stream = null;
                        entry.OwnsStream = false;
                    }

                    return position;
                });
                if (IsCompressed) {
                    writer.Write((uint)(entry.Stream?.Length ?? entry.UnpackedLength));
                }
            }
        });

        writer.PerformScheduledWrites();
        writer.Align(mAlignment, 0x78);
    }

    protected override void Dispose(bool disposing) {
        if (disposing) {
            foreach (Entry entry in mEntries.Values) {
                entry.Dispose();
            }
        }

        base.Dispose(disposing);
    }

    private static Aes CreateAes() {
        Aes aes = Aes.Create();
        aes.KeySize = 128;
        aes.Key = new byte[] {
            // project_diva.bin
            0x70, 0x72, 0x6F, 0x6A, 0x65, 0x63, 0x74, 0x5F, 0x64, 0x69, 0x76, 0x61, 0x2E, 0x62, 0x69, 0x6E
        };
        aes.BlockSize = 128;
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.Zeros;
        aes.IV = new byte[16];
        return aes;
    }

    private static Aes CreateAesForFt(byte[] iv = null) {
        Aes aes = Aes.Create();
        aes.KeySize = 128;
        aes.Key = new byte[] {
            0x13, 0x72, 0xD5, 0x7B, 0x6E, 0x9E, 0x31, 0xEB, 0xA2, 0x39, 0xB8, 0x3C, 0x15, 0x57, 0xC6, 0xBB
        };
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.Zeros;
        aes.IV = iv ?? new byte[16];
        return aes;
    }

    private static Aes CreateAesForFgo(byte[] iv = null) {
        Aes aes = Aes.Create();
        aes.KeySize = 128;
        aes.Key = new byte[] {
            0x62, 0xEC, 0x7C, 0xD7, 0x91, 0x41, 0x69, 0x5E, 0x53, 0x59, 0x2A, 0xCC, 0x10, 0xCD, 0xC0, 0x4C
        };
        aes.BlockSize = 128;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.Zeros;
        aes.IV = iv ?? new byte[16];
        return aes;
    }

    private class Entry : IDisposable {
        public string Name;
        public long Position;
        public long Length;
        public long CompressedLength;
        public long UnpackedLength;
        public Stream Stream;
        public bool OwnsStream;

        public bool IsGzipCompressed;
        public bool IsZstdCompressed;
        public bool IsEncrypted;
        public bool IsFutureTone;
        public bool IsFate;

        public void Dispose() {
            if (OwnsStream) {
                Stream?.Dispose();
            }
        }

        public Stream Open(Stream source) {
            if (Stream != null) {
                return Stream;
            }

            if (Length == 0 || UnpackedLength == 0) {
                return Stream.Null;
            }

            Stream stream = source;

            stream.Seek(Position, SeekOrigin.Begin);

            if (IsEncrypted) {
                stream = GetDecryptingStream(stream, true);
            }

            if (IsGzipCompressed) {
                stream = GetDecompressingStream(stream, stream == source);
            } else if (IsZstdCompressed) {
                stream = GetZstdDecompressingStream(stream);
            }

            long position = Position;

            if ((IsFutureTone || IsFate) && IsEncrypted) {
                position += 16;
            }

            return new StreamView(stream, source, position, UnpackedLength, stream == source);
        }

        internal void CopyTo(Stream destination, Stream source, bool compress) {
            if (Stream != null) {
                if (Stream.Length == 0) {
                    return;
                }

                Stream.Seek(0, SeekOrigin.Begin);
                CopyCompressedIf(compress, Stream);
                return;
            }

            if (Length == 0 || UnpackedLength == 0) {
                return;
            }

            source.Seek(Position, SeekOrigin.Begin);

            Stream sourceStream;

            if (IsEncrypted) {
                StreamView streamView = new StreamView(source, Position, Length, true);
                sourceStream = new StreamView(GetDecryptingStream(streamView), streamView, 0, IsGzipCompressed ? CompressedLength : UnpackedLength);
            } else if (IsGzipCompressed || IsZstdCompressed) {
                sourceStream = new StreamView(source, Position, CompressedLength, true);
            } else {
                sourceStream = new StreamView(source, Position, UnpackedLength, true);
            }

            if (IsGzipCompressed && !compress) {
                sourceStream = new StreamView(GetDecompressingStream(sourceStream, sourceStream == source), sourceStream, 0, UnpackedLength);
            } else if (IsGzipCompressed && !compress) {
                sourceStream = new StreamView(GetZstdDecompressingStream(sourceStream), sourceStream, 0, UnpackedLength);
            }

            CopyCompressedIf(!IsGzipCompressed && !IsZstdCompressed && compress, sourceStream);

            sourceStream.Close();
            return;

            void CopyCompressedIf(bool condition, Stream stream) {
                if (condition) {
                    using (GZipStream gzipStream = new GZipStream(destination, CompressionMode.Compress, true)) {
                        stream.CopyTo(gzipStream);
                    }
                } else {
                    stream.CopyTo(destination);
                }
            }
        }

        private CryptoStream GetDecryptingStream(Stream stream, bool leaveOpen = false) {
            Aes aes;

            if (IsFutureTone || IsFate) {
                byte[] iv = new byte[16];
                stream.ReadExactly(iv, 0, 16);

                aes = IsFate ? CreateAesForFgo(iv) : CreateAesForFt(iv);
            } else {
                aes = CreateAes();
            }

            ICryptoTransform decryptor = aes.CreateDecryptor();
            return new NonClosingCryptoStream(stream, decryptor, CryptoStreamMode.Read, leaveOpen);
        }

        private static GZipStream GetDecompressingStream(Stream stream, bool leaveOpen = false) {
            return new GZipStream(stream, CompressionMode.Decompress, leaveOpen);
        }

        private static DecompressionStream GetZstdDecompressingStream(Stream stream) {
            return new DecompressionStream(stream);
        }

        private class NonClosingCryptoStream : CryptoStream {
            private readonly bool mLeaveOpen;

            protected override void Dispose(bool disposing) {
                if (!HasFlushedFinalBlock) {
                    FlushFinalBlock();
                }

                base.Dispose(!mLeaveOpen);
            }

            public NonClosingCryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode, bool leaveOpen)
                : base(stream, transform, mode) {
                mLeaveOpen = leaveOpen;
            }
        }
    }
}