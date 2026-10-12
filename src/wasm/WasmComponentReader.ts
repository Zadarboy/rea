/**
 * Structural failure at an absolute file offset. `malformed` breaks the
 * pinned grammar's framing; `unsupported` is a well-framed construct the
 * decoder does not decode.
 */
export class WasmComponentFormatFailure extends Error {
  constructor(
    readonly kind: "malformed" | "unsupported",
    readonly offset: number,
    message: string,
  ) {
    super(`${message} at offset ${String(offset)}`);
    this.name = "WasmComponentFormatFailure";
  }
}

const UTF8 = new TextDecoder("utf-8", { fatal: true });

/** Bounded cursor over one byte range; every offset is an absolute file offset. */
export class WasmComponentReader {
  #offset: number;

  constructor(
    private readonly bytes: Uint8Array,
    start: number,
    readonly end: number,
  ) {
    this.#offset = start;
  }

  get offset(): number {
    return this.#offset;
  }

  get atEnd(): boolean {
    return this.#offset >= this.end;
  }

  malformed(message: string, at = this.#offset): WasmComponentFormatFailure {
    return new WasmComponentFormatFailure("malformed", at, message);
  }

  unsupported(message: string, at = this.#offset): WasmComponentFormatFailure {
    return new WasmComponentFormatFailure("unsupported", at, message);
  }

  byte(context: string): number {
    if (this.#offset >= this.end)
      throw this.malformed(`Unexpected end of ${context}`);
    const value = this.bytes[this.#offset];
    if (value === undefined)
      throw this.malformed(`Unexpected end of ${context}`);
    this.#offset += 1;
    return value;
  }

  /** The next byte without consuming it, or undefined at the end. */
  peek(): number | undefined {
    return this.#offset < this.end ? this.bytes[this.#offset] : undefined;
  }

  /**
   * Unsigned LEB128 limited to 32 bits, as in core WebAssembly: the fifth
   * byte ends the value and carries only its top four bits.
   */
  u32(context: string): number {
    const start = this.#offset;
    let result = 0;
    for (let index = 0; index < 4; index += 1) {
      const byte = this.byte(context);
      result += (byte & 0x7f) * 2 ** (7 * index);
      if ((byte & 0x80) === 0) return result;
    }
    const last = this.byte(context);
    if (last > 0x0f)
      throw this.malformed(`Invalid u32 LEB128 in ${context}`, start);
    return result + last * 2 ** 28;
  }

  /** Unsigned LEB128 limited to 64 bits; values above 2^53 are not decoded. */
  u64(context: string): number {
    const start = this.#offset;
    let result = 0n;
    for (let index = 0; index < 10; index += 1) {
      const byte = this.byte(context);
      if (index === 9 && byte > 0x01)
        throw this.malformed(`Invalid u64 LEB128 in ${context}`, start);
      result |= BigInt(byte & 0x7f) << BigInt(7 * index);
      if ((byte & 0x80) === 0) {
        if (result > BigInt(Number.MAX_SAFE_INTEGER))
          throw this.unsupported(
            `${context} exceeds 2^53 and is not decoded`,
            start,
          );
        return Number(result);
      }
    }
    throw this.malformed(`Overlong u64 LEB128 in ${context}`, start);
  }

  /** Signed 33-bit LEB128 used by core heap types. */
  s33(context: string): number {
    const start = this.#offset;
    let result = 0;
    for (let index = 0; index < 5; index += 1) {
      const byte = this.byte(context);
      result += (byte & 0x7f) * 2 ** (7 * index);
      if ((byte & 0x80) === 0) {
        const bits = 7 * (index + 1);
        if (index === 4) {
          const high = byte & 0x70;
          if (high !== 0 && high !== 0x70)
            throw this.malformed(`Invalid s33 LEB128 in ${context}`, start);
        }
        return (byte & 0x40) !== 0 && bits < 64 ? result - 2 ** bits : result;
      }
    }
    throw this.malformed(`Overlong s33 LEB128 in ${context}`, start);
  }

  /** Length-prefixed UTF-8 text, as `core:name`. */
  name(context: string): string {
    const length = this.u32(`${context} length`);
    const { start, end } = this.range(length, context);
    try {
      return UTF8.decode(this.bytes.subarray(start, end));
    } catch (cause: unknown) {
      void cause;
      throw this.malformed(`Invalid UTF-8 in ${context}`, start);
    }
  }

  /** Consume `length` bytes and return their absolute range. */
  range(length: number, context: string): { start: number; end: number } {
    const start = this.#offset;
    if (length > this.end - start)
      throw this.malformed(`${context} extends past its enclosing range`);
    this.#offset += length;
    return { start, end: this.#offset };
  }

  /** Reader limited to the next `length` bytes, which this reader skips. */
  sub(length: number, context: string): WasmComponentReader {
    const { start, end } = this.range(length, context);
    return new WasmComponentReader(this.bytes, start, end);
  }

  /** Vector length bounded by the bytes that could encode its elements. */
  count(context: string): number {
    const at = this.#offset;
    const count = this.u32(`${context} count`);
    if (count > this.end - this.#offset)
      throw this.malformed(`${context} count exceeds its remaining bytes`, at);
    return count;
  }

  expectEnd(context: string): void {
    if (this.#offset !== this.end)
      throw this.malformed(`Unexpected trailing bytes in ${context}`);
  }
}
