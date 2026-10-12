import type {
  BinaryArchitecture,
  ElfFamilyMetadata,
  HeaderArchitecture,
  MipsElfMetadata,
  PeCodeViewRecord,
  RiscvElfMetadata,
  UniversalMachOSlice,
} from "./binaryTargetTypes.js";
import { err, ok, type Result } from "./result.js";
import { observeMzWindowsHeader, parseDosMzHeader } from "./dosMz.js";
import { decodePeMachine } from "./peMachine.js";

/** Format and architecture facts recovered from an executable header. */
export type ExecutableMetadata =
  | {
      readonly format: "elf";
      readonly architecture: "mips";
      readonly availableArchitectures: readonly "mips"[];
      readonly mips: MipsElfMetadata;
    }
  | {
      readonly format: "elf";
      readonly architecture: "riscv";
      readonly availableArchitectures: readonly "riscv"[];
      readonly riscv: RiscvElfMetadata;
    }
  | {
      readonly format: "mach-o" | "elf" | "dos-mz" | "dos-com";
      readonly architecture: HeaderArchitecture;
      readonly availableArchitectures: readonly HeaderArchitecture[];
      readonly universalSlice?: never;
    }
  | {
      readonly format: "mach-o-universal";
      readonly architecture: HeaderArchitecture;
      readonly availableArchitectures: readonly HeaderArchitecture[];
      readonly universalSlice: UniversalMachOSlice;
    }
  | {
      readonly format: "pe";
      readonly architecture: HeaderArchitecture;
      readonly availableArchitectures: readonly HeaderArchitecture[];
      readonly executableRole:
        | "application"
        | "shared-library"
        | "non-executable";
      readonly managed: boolean;
      readonly codeView?: PeCodeViewRecord;
    };

/**
 * Parse supported executable headers without I/O. The caller supplies the host
 * architecture used for deterministic FAT Mach-O slice selection.
 */
export const parseExecutableHeader = (
  bytes: Buffer,
  hostArchitecture: NodeJS.Architecture,
  fileSize = bytes.length,
  mzWindowsHeaderSignature?: Buffer,
): Result<ExecutableMetadata, string> => {
  if (
    bytes.length >= 4 &&
    bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
  )
    return parseElf(bytes, fileSize);
  if (bytes.length >= 2 && bytes[0] === 0x4d && bytes[1] === 0x5a)
    return parseMz(bytes, fileSize, mzWindowsHeaderSignature);
  if (bytes.length < 8) return err("truncated or unsupported binary header");
  const magic = bytes.readUInt32BE(0);
  if ([0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe].includes(magic))
    return parseThinMachO(bytes, magic, fileSize);
  if ([0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca].includes(magic))
    return parseFatMachO(bytes, magic, hostArchitecture, fileSize);
  return err("unsupported binary format");
};

const parseThinMachO = (
  bytes: Buffer,
  magic: number,
  fileSize: number,
): Result<ExecutableMetadata, string> => {
  const is64 = magic === 0xfeedfacf || magic === 0xcffaedfe;
  const headerSize = is64 ? 32 : 28;
  if (bytes.length < headerSize)
    return err(
      `truncated Mach-O header: a ${is64 ? 64 : 32}-bit header needs ${headerSize} bytes; the file has ${fileSize}`,
    );
  const little = magic === 0xcefaedfe || magic === 0xcffaedfe;
  const read = (offset: number): number =>
    little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const architecture = machArchitecture(read(4));
  if (architecture === undefined) return err("unsupported Mach-O architecture");
  const commandBytes = read(20);
  if (headerSize + commandBytes > fileSize)
    return err(
      `truncated Mach-O load commands: the header declares ${commandBytes} bytes after its ${headerSize}-byte header; the file has ${fileSize}`,
    );
  return ok({
    format: "mach-o",
    architecture,
    availableArchitectures: [architecture],
  });
};

const parseFatMachO = (
  bytes: Buffer,
  magic: number,
  host: NodeJS.Architecture,
  fileSize: number,
): Result<ExecutableMetadata, string> => {
  const little = magic === 0xbebafeca || magic === 0xbfbafeca;
  const is64 = magic === 0xcafebabf || magic === 0xbfbafeca;
  if (bytes.length < 8) return err("truncated FAT header");
  const read = (offset: number): number =>
    little ? bytes.readUInt32LE(offset) : bytes.readUInt32BE(offset);
  const count = read(4);
  const entrySize = is64 ? 32 : 20;
  if (count === 0 || count > 128 || bytes.length < 8 + count * entrySize)
    return err("truncated or invalid FAT architecture table");
  const architectures: HeaderArchitecture[] = [];
  const slices = new Map<
    HeaderArchitecture,
    { readonly offset: bigint; readonly size: bigint }
  >();
  for (let index = 0; index < count; index += 1) {
    const entry = 8 + index * entrySize;
    const architecture = machArchitecture(read(entry));
    if (architecture === undefined || architectures.includes(architecture))
      continue;
    architectures.push(architecture);
    const offset = is64
      ? little
        ? bytes.readBigUInt64LE(entry + 8)
        : bytes.readBigUInt64BE(entry + 8)
      : BigInt(read(entry + 8));
    const size = is64
      ? little
        ? bytes.readBigUInt64LE(entry + 16)
        : bytes.readBigUInt64BE(entry + 16)
      : BigInt(read(entry + 12));
    slices.set(architecture, { offset, size });
  }
  const preferred =
    host === "arm64"
      ? "arm64"
      : host === "x64"
        ? "x86_64"
        : host === "ia32"
          ? "x86"
          : host === "arm"
            ? "arm"
            : undefined;
  const slice = preferred === undefined ? undefined : slices.get(preferred);
  if (preferred === undefined || slice === undefined)
    return err(`FAT binary has no host-compatible ${host} architecture`);
  const tableEnd = BigInt(8 + count * entrySize);
  if (slice.offset < tableEnd)
    return err(`FAT slice for ${preferred} overlaps the architecture table`);
  const minimumHeaderSize =
    preferred === "arm64" || preferred === "x86_64" ? 32n : 28n;
  if (slice.size < minimumHeaderSize)
    return err(`FAT slice for ${preferred} is shorter than its Mach-O header`);
  const sliceEnd = slice.offset + slice.size;
  if (sliceEnd > BigInt(fileSize))
    return err(
      `truncated FAT slice: the ${preferred} slice ends at byte ${sliceEnd}; the file has ${fileSize}`,
    );
  const sliceOffset = Number(slice.offset);
  const sliceSize = Number(slice.size);
  if (!Number.isSafeInteger(sliceOffset) || !Number.isSafeInteger(sliceSize))
    return err(`FAT slice for ${preferred} exceeds addressable byte bounds`);
  return ok({
    format: "mach-o-universal",
    architecture: preferred,
    availableArchitectures: architectures,
    universalSlice: { offset: sliceOffset, size: sliceSize },
  });
};

const parseElf = (
  bytes: Buffer,
  fileSize: number,
): Result<ExecutableMetadata, string> => {
  if (bytes.length < 6) return err("truncated ELF header");
  if (bytes[4] !== 1 && bytes[4] !== 2) return err("unsupported ELF class");
  const little = bytes[5] === 1;
  if (!little && bytes[5] !== 2) return err("unsupported ELF endianness");
  const headerSize = bytes[4] === 1 ? 52 : 64;
  if (bytes.length < headerSize)
    return err(
      `truncated ELF header: an ELF${bytes[4] === 1 ? 32 : 64} header needs ${headerSize} bytes; the file has ${fileSize}`,
    );
  const machine = little ? bytes.readUInt16LE(18) : bytes.readUInt16BE(18);
  const architecture = elfArchitecture(machine);
  if (architecture === undefined) return err("unsupported ELF architecture");
  if (architecture === "mips" || architecture === "riscv") {
    const elfClass = bytes[4] === 1 ? 32 : 64;
    const flagsOffset = elfClass === 32 ? 36 : 48;
    const metadata: ElfFamilyMetadata = {
      elfClass,
      byteOrder: little ? "little" : "big",
      type: little ? bytes.readUInt16LE(16) : bytes.readUInt16BE(16),
      flags: little
        ? bytes.readUInt32LE(flagsOffset)
        : bytes.readUInt32BE(flagsOffset),
    };
    return architecture === "mips"
      ? ok({
          format: "elf",
          architecture,
          availableArchitectures: [architecture],
          mips: metadata,
        })
      : ok({
          format: "elf",
          architecture,
          availableArchitectures: [architecture],
          riscv: metadata,
        });
  }
  return ok({
    format: "elf",
    architecture,
    availableArchitectures: [architecture],
  });
};

const parseMz = (
  bytes: Buffer,
  fileSize: number,
  signatureAtOffset?: Buffer,
): Result<ExecutableMetadata, string> => {
  const windowsHeader = observeMzWindowsHeader(
    bytes,
    fileSize,
    signatureAtOffset,
  );
  if (
    windowsHeader.state === "header-needed" ||
    windowsHeader.state === "signature-needed"
  )
    return err(
      "Windows new-header pointer or signature is outside the bounded prefix",
    );
  if (windowsHeader.state === "declared") {
    const { offset } = windowsHeader;
    if (offset < 64 || offset > bytes.length - 24)
      return err("invalid or truncated Windows executable header in MZ image");
    if (["NE", "LE", "LX"].includes(windowsHeader.signature))
      return err(
        `unsupported ${windowsHeader.signature} executable in MZ image`,
      );
    if (windowsHeader.signature !== "PE")
      return err("invalid or truncated Windows executable header in MZ image");
    const codeView = parsePeCodeViewFromBuffer(bytes, offset);
    return parsePeRecord(bytes.subarray(offset), codeView);
  }
  const parsed = parseDosMzHeader(bytes, fileSize, signatureAtOffset);
  return parsed.ok
    ? ok({
        format: "dos-mz",
        architecture: "x86",
        availableArchitectures: ["x86"],
      })
    : parsed;
};

/** Parse a bounded PE signature, COFF record, and optional header without I/O. */
export const parsePeRecord = (
  record: Buffer,
  codeView?: PeCodeViewRecord,
): Result<ExecutableMetadata, string> => {
  if (
    record.length < 24 ||
    record.toString("binary", 0, 4) !== "PE\u0000\u0000"
  )
    return err("invalid or truncated PE header");
  const machine = decodePeMachine(record.readUInt16LE(4));
  if (machine === undefined) return err("unsupported PE architecture");
  const { architecture } = machine;
  const optionalHeaderSize = record.readUInt16LE(20);
  if (optionalHeaderSize > 4096 || record.length < 24 + optionalHeaderSize)
    return err("invalid or truncated PE optional header");
  const optionalHeader = record.subarray(24, 24 + optionalHeaderSize);
  const managed = peManagedStatus(optionalHeader, architecture);
  if (!managed.ok) return managed;
  if (machine.nativeOsOverride && !managed.value)
    return err("unsupported PE architecture");
  const characteristics = record.readUInt16LE(22);
  const resolvedCodeView = codeView ?? parsePeCodeViewFromBuffer(record, 0);
  return ok({
    format: "pe",
    architecture,
    availableArchitectures: [architecture],
    executableRole:
      (characteristics & 0x0002) === 0
        ? "non-executable"
        : (characteristics & 0x2000) === 0
          ? "application"
          : "shared-library",
    managed: managed.value,
    ...(resolvedCodeView !== undefined ? { codeView: resolvedCodeView } : {}),
  });
};

/** Parse CodeView record data (RSDS or NB10) from raw data bytes. */
export const parseCodeViewData = (
  buffer: Buffer,
  sizeOfData: number,
): PeCodeViewRecord | undefined => {
  if (sizeOfData < 16 || buffer.length < 16) return undefined;
  const magic = buffer.subarray(0, 4).toString("ascii");
  if (magic === "RSDS" && sizeOfData >= 24 && buffer.length >= 24) {
    const part1 = buffer.readUInt32LE(4).toString(16).padStart(8, "0");
    const part2 = buffer.readUInt16LE(8).toString(16).padStart(4, "0");
    const part3 = buffer.readUInt16LE(10).toString(16).padStart(4, "0");
    const part4 = buffer.subarray(12, 14).toString("hex");
    const part5 = buffer.subarray(14, 20).toString("hex");
    const guid = `${part1}-${part2}-${part3}-${part4}-${part5}`;
    const age = buffer.readUInt32LE(20);
    const nullIdx = buffer.indexOf(0, 24);
    const end =
      nullIdx !== -1 && nullIdx < sizeOfData
        ? nullIdx
        : Math.min(sizeOfData, buffer.length);
    const pdbPath = buffer.toString("utf8", 24, end);
    const pdbFileName = pdbPath.split(/[/\\]/u).pop() ?? pdbPath;
    return { pdbPath, pdbFileName, guid, age };
  }
  if (magic === "NB10") {
    const age = buffer.readUInt32LE(12);
    const nullIdx = buffer.indexOf(0, 16);
    const end =
      nullIdx !== -1 && nullIdx < sizeOfData
        ? nullIdx
        : Math.min(sizeOfData, buffer.length);
    const pdbPath = buffer.toString("utf8", 16, end);
    const pdbFileName = pdbPath.split(/[/\\]/u).pop() ?? pdbPath;
    return { pdbPath, pdbFileName, guid: null, age };
  }
  return undefined;
};

/** Locate the debug directory RVA and size from a PE optional header. */
export const peDebugDirectoryEntry = (
  optionalHeader: Buffer,
): { readonly debugRva: number; readonly debugSize: number } | undefined => {
  if (optionalHeader.length < 2) return undefined;
  const magic = optionalHeader.readUInt16LE(0);
  if (magic !== 0x10b && magic !== 0x20b) return undefined;
  const directoryOffset = magic === 0x20b ? 112 : 96;
  const directoryCountOffset = directoryOffset - 4;
  if (optionalHeader.length < directoryCountOffset + 4) return undefined;
  const directoryCount = optionalHeader.readUInt32LE(directoryCountOffset);
  if (directoryCount <= 6) return undefined;
  const debugEntryOffset = directoryOffset + 6 * 8;
  if (optionalHeader.length < debugEntryOffset + 8) return undefined;
  const debugRva = optionalHeader.readUInt32LE(debugEntryOffset);
  const debugSize = optionalHeader.readUInt32LE(debugEntryOffset + 4);
  if (debugRva === 0 || debugSize < 28) return undefined;
  return { debugRva, debugSize };
};

/** Translate an RVA to an absolute file offset using the PE section table. */
export const peRvaToFileOffset = (
  rva: number,
  sectionTable: Buffer,
  numberOfSections: number,
): number | undefined => {
  for (let i = 0; i < numberOfSections; i++) {
    const offset = i * 40;
    if (sectionTable.length < offset + 40) break;
    const virtualAddress = sectionTable.readUInt32LE(offset + 12);
    const sizeOfRawData = sectionTable.readUInt32LE(offset + 16);
    const pointerToRawData = sectionTable.readUInt32LE(offset + 20);
    if (
      pointerToRawData > 0 &&
      rva >= virtualAddress &&
      rva - virtualAddress < sizeOfRawData
    ) {
      return pointerToRawData + (rva - virtualAddress);
    }
  }
  return undefined;
};

/** Parse CodeView metadata from a bounded in-memory PE image buffer. */
export const parsePeCodeViewFromBuffer = (
  fileBytes: Buffer,
  peOffset: number,
): PeCodeViewRecord | undefined => {
  if (fileBytes.length < peOffset + 24) return undefined;
  const numberOfSections = fileBytes.readUInt16LE(peOffset + 6);
  const optionalHeaderSize = fileBytes.readUInt16LE(peOffset + 20);
  if (
    optionalHeaderSize > 4096 ||
    fileBytes.length < peOffset + 24 + optionalHeaderSize
  )
    return undefined;
  const optionalHeader = fileBytes.subarray(
    peOffset + 24,
    peOffset + 24 + optionalHeaderSize,
  );
  const debugDir = peDebugDirectoryEntry(optionalHeader);
  if (debugDir === undefined) return undefined;
  const sectionTableOffset = peOffset + 24 + optionalHeaderSize;
  const sectionTableSize = numberOfSections * 40;
  if (fileBytes.length < sectionTableOffset + sectionTableSize)
    return undefined;
  const sectionTable = fileBytes.subarray(
    sectionTableOffset,
    sectionTableOffset + sectionTableSize,
  );
  const debugFileOffset = peRvaToFileOffset(
    debugDir.debugRva,
    sectionTable,
    numberOfSections,
  );
  if (debugFileOffset === undefined || fileBytes.length < debugFileOffset + 28)
    return undefined;
  const maxDebugBytes = Math.min(
    debugDir.debugSize,
    fileBytes.length - debugFileOffset,
  );
  const numEntries = Math.floor(maxDebugBytes / 28);
  for (let j = 0; j < numEntries; j++) {
    const entryOffset = debugFileOffset + j * 28;
    const type = fileBytes.readUInt32LE(entryOffset + 12);
    if (type !== 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
    const sizeOfData = fileBytes.readUInt32LE(entryOffset + 16);
    let pointerToRawData = fileBytes.readUInt32LE(entryOffset + 24);
    if (pointerToRawData === 0) {
      const addressOfRawData = fileBytes.readUInt32LE(entryOffset + 20);
      const mapped = peRvaToFileOffset(
        addressOfRawData,
        sectionTable,
        numberOfSections,
      );
      if (mapped === undefined) continue;
      pointerToRawData = mapped;
    }
    if (
      sizeOfData < 16 ||
      fileBytes.length < pointerToRawData + Math.min(sizeOfData, 24)
    )
      continue;
    const codeViewData = fileBytes.subarray(
      pointerToRawData,
      Math.min(fileBytes.length, pointerToRawData + sizeOfData),
    );
    const parsed = parseCodeViewData(codeViewData, sizeOfData);
    if (parsed !== undefined) return parsed;
  }
  return undefined;
};

const peManagedStatus = (
  optionalHeader: Buffer,
  architecture: BinaryArchitecture,
): Result<boolean, string> => {
  if (optionalHeader.length < 2) return err("truncated PE optional header");
  const magic = optionalHeader.readUInt16LE(0);
  const expectedMagic =
    architecture === "x86_64" || architecture === "arm64" ? 0x20b : 0x10b;
  if (magic !== expectedMagic)
    return err("PE optional-header magic does not match its architecture");
  const directoryOffset = magic === 0x20b ? 112 : 96;
  const directoryCountOffset = directoryOffset - 4;
  if (optionalHeader.length < directoryCountOffset + 4)
    return err("truncated PE optional header");
  const directoryCount = optionalHeader.readUInt32LE(directoryCountOffset);
  const requiredBytes = directoryOffset + directoryCount * 8;
  if (
    !Number.isSafeInteger(requiredBytes) ||
    requiredBytes > optionalHeader.length
  )
    return err("truncated PE data-directory table");
  if (directoryCount <= 14) return ok(false);
  const cliDirectory = directoryOffset + 14 * 8;
  return ok(
    optionalHeader.readUInt32LE(cliDirectory) !== 0 ||
      optionalHeader.readUInt32LE(cliDirectory + 4) !== 0,
  );
};

const machArchitecture = (cpu: number): HeaderArchitecture | undefined => {
  switch (cpu) {
    case 7:
      return "x86";
    case 0x01000007:
      return "x86_64";
    case 12:
      return "arm";
    case 0x0100000c:
      return "arm64";
  }
  return undefined;
};

const elfArchitecture = (machine: number): BinaryArchitecture | undefined => {
  switch (machine) {
    case 3:
      return "x86";
    case 62:
      return "x86_64";
    case 8: // EM_MIPS: ISA, ABI and byte order remain separate ELF facts.
      return "mips";
    case 40:
      return "arm";
    case 183:
      return "arm64";
    case 243: // EM_RISCV: XLEN, byte order and e_flags remain separate ELF facts.
      return "riscv";
  }
  return undefined;
};
