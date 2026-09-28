// A ZIP holding one file behind the traditional PKWARE password. That cipher is weak, and it is not here to
// keep a secret: it is how malware travels between analysts, because no mail filter, antivirus or double
// click opens what it wraps, while every archive tool on every system can.

import { randomBytes } from "node:crypto";
import { deflateRawSync, inflateRawSync } from "node:zlib";

const CRC_POLYNOMIAL = 0xedb88320;
const CRC_TABLE = Uint32Array.from({ length: 256 }, (_, index) => {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
        value = value & 1 ? CRC_POLYNOMIAL ^ (value >>> 1) : value >>> 1;
    }
    return value >>> 0;
});

const LOCAL_HEADER_SIGNATURE = 0x04034b50;
const CENTRAL_HEADER_SIGNATURE = 0x02014b50;
const END_OF_DIRECTORY_SIGNATURE = 0x06054b50;
const VERSION_NEEDED = 20;
const FLAG_ENCRYPTED = 0x0001;
const FLAG_UTF8_NAME = 0x0800;
const METHOD_STORED = 0;
const METHOD_DEFLATED = 8;
const ENCRYPTION_HEADER_BYTES = 12;
const LOCAL_HEADER_BYTES = 30;
const CENTRAL_HEADER_BYTES = 46;
const END_OF_DIRECTORY_BYTES = 22;
const KEY_MULTIPLIER = 134775813;
const DOS_EPOCH_YEAR = 1980;
const MAX_ENTRIES = 10_000;

function crcByte(crc: number, byte: number): number {
    return (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
}

export function crc32(data: Uint8Array): number {
    let crc = 0xffffffff;
    for (const byte of data) crc = crcByte(crc, byte);
    return (crc ^ 0xffffffff) >>> 0;
}

/** The three keys of the traditional cipher, stirred by every byte of the password and of the plain text. */
export class ZipCryptoKeys {
    private keys = [0x12345678, 0x23456789, 0x34567890];

    constructor(password: string) {
        for (const byte of Buffer.from(password, "utf8")) this.update(byte);
    }

    update(plain: number): void {
        const [first = 0, second = 0, third = 0] = this.keys;
        const nextFirst = crcByte(first, plain) >>> 0;
        const nextSecond = (Math.imul((second + (nextFirst & 0xff)) >>> 0, KEY_MULTIPLIER) + 1) >>> 0;
        const nextThird = crcByte(third, nextSecond >>> 24) >>> 0;
        this.keys = [nextFirst, nextSecond, nextThird];
    }

    streamByte(): number {
        const temp = ((this.keys[2] ?? 0) | 2) & 0xffff;
        return ((temp * (temp ^ 1)) >>> 8) & 0xff;
    }

    encrypt(plain: number): number {
        const cipher = plain ^ this.streamByte();
        this.update(plain);
        return cipher;
    }
}

function dosTime(date: Date): { time: number; date: number } {
    return {
        time: (date.getHours() << 11) | (date.getMinutes() << 5) | Math.floor(date.getSeconds() / 2),
        date: ((Math.max(date.getFullYear(), DOS_EPOCH_YEAR) - DOS_EPOCH_YEAR) << 9) | ((date.getMonth() + 1) << 5) | date.getDate()
    };
}

export interface ZipEntry {
    name: string;
    content: Uint8Array;
    /** Locks the entry with the traditional PKWARE password. */
    password?: string;
    /** Compresses the entry, which pays for text and not for files that are packed already. */
    compress?: boolean;
}

function seal(data: Uint8Array, crc: number, password: string): Buffer {
    // Eleven random bytes, then the top byte of the CRC, which is how a reader checks the password
    const header = randomBytes(ENCRYPTION_HEADER_BYTES);
    header[ENCRYPTION_HEADER_BYTES - 1] = crc >>> 24;
    const keys = new ZipCryptoKeys(password);
    const sealed = Buffer.alloc(ENCRYPTION_HEADER_BYTES + data.length);
    header.forEach((byte, index) => { sealed[index] = keys.encrypt(byte); });
    data.forEach((byte, index) => { sealed[ENCRYPTION_HEADER_BYTES + index] = keys.encrypt(byte); });
    return sealed;
}

/** Writes an archive of the entries, each stored or compressed, locked or not, in the order given. */
export function zipArchive(entries: readonly ZipEntry[], modified: Date = new Date()): Buffer {
    const stamp = dosTime(modified);
    const locals: Buffer[] = [];
    const centrals: Buffer[] = [];
    let offset = 0;

    for (const entry of entries) {
        const name = Buffer.from(entry.name, "utf8");
        const crc = crc32(entry.content);
        const method = entry.compress ? METHOD_DEFLATED : METHOD_STORED;
        const packed = entry.compress ? deflateRawSync(entry.content) : Buffer.from(entry.content);
        const data = entry.password === undefined ? packed : seal(packed, crc, entry.password);
        const flags = FLAG_UTF8_NAME | (entry.password === undefined ? 0 : FLAG_ENCRYPTED);

        const local = Buffer.alloc(LOCAL_HEADER_BYTES);
        local.writeUInt32LE(LOCAL_HEADER_SIGNATURE, 0);
        local.writeUInt16LE(VERSION_NEEDED, 4);
        local.writeUInt16LE(flags, 6);
        local.writeUInt16LE(method, 8);
        local.writeUInt16LE(stamp.time, 10);
        local.writeUInt16LE(stamp.date, 12);
        local.writeUInt32LE(crc, 14);
        local.writeUInt32LE(data.length, 18);
        local.writeUInt32LE(entry.content.length, 22);
        local.writeUInt16LE(name.length, 26);

        const central = Buffer.alloc(CENTRAL_HEADER_BYTES);
        central.writeUInt32LE(CENTRAL_HEADER_SIGNATURE, 0);
        central.writeUInt16LE(VERSION_NEEDED, 4);
        central.writeUInt16LE(VERSION_NEEDED, 6);
        central.writeUInt16LE(flags, 8);
        central.writeUInt16LE(method, 10);
        central.writeUInt16LE(stamp.time, 12);
        central.writeUInt16LE(stamp.date, 14);
        central.writeUInt32LE(crc, 16);
        central.writeUInt32LE(data.length, 20);
        central.writeUInt32LE(entry.content.length, 24);
        central.writeUInt16LE(name.length, 28);
        central.writeUInt32LE(offset, 42);

        locals.push(local, name, data);
        centrals.push(central, name);
        offset += local.length + name.length + data.length;
    }

    const directory = Buffer.concat(centrals);
    const end = Buffer.alloc(END_OF_DIRECTORY_BYTES);
    end.writeUInt32LE(END_OF_DIRECTORY_SIGNATURE, 0);
    end.writeUInt16LE(entries.length, 8);
    end.writeUInt16LE(entries.length, 10);
    end.writeUInt32LE(directory.length, 12);
    end.writeUInt32LE(offset, 16);
    return Buffer.concat([...locals, directory, end]);
}

/**
 * Wraps one file in a ZIP locked with the password. The file is stored rather than compressed, since a
 * sample is often packed already and what matters is that it arrives intact.
 */
export function lockedZip(entryName: string, content: Uint8Array, password: string, modified: Date = new Date()): Buffer {
    return zipArchive([{ name: entryName, content, password }], modified);
}

export class ZipFormatError extends Error {}

/**
 * Reads the entries of an archive through its central directory, unlocking those locked with the password.
 * It reads what zipArchive writes and the plain archives of common tools; ZIP64 and other ciphers are refused.
 */
export function readZip(archive: Buffer, password?: string): Map<string, Buffer> {
    const endAt = archive.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (endAt < 0 || endAt + END_OF_DIRECTORY_BYTES > archive.length) throw new ZipFormatError("This is not a ZIP archive.");
    const count = archive.readUInt16LE(endAt + 10);
    if (count > MAX_ENTRIES) throw new ZipFormatError("The archive holds too many entries.");
    let cursor = archive.readUInt32LE(endAt + 16);

    const entries = new Map<string, Buffer>();
    for (let index = 0; index < count; index += 1) {
        if (cursor + CENTRAL_HEADER_BYTES > archive.length || archive.readUInt32LE(cursor) !== CENTRAL_HEADER_SIGNATURE) {
            throw new ZipFormatError("The directory of the archive is damaged.");
        }
        const flags = archive.readUInt16LE(cursor + 8);
        const method = archive.readUInt16LE(cursor + 10);
        const crc = archive.readUInt32LE(cursor + 16);
        const packedSize = archive.readUInt32LE(cursor + 20);
        const size = archive.readUInt32LE(cursor + 24);
        const nameLength = archive.readUInt16LE(cursor + 28);
        const extraLength = archive.readUInt16LE(cursor + 30);
        const commentLength = archive.readUInt16LE(cursor + 32);
        const localAt = archive.readUInt32LE(cursor + 42);
        const name = archive.subarray(cursor + CENTRAL_HEADER_BYTES, cursor + CENTRAL_HEADER_BYTES + nameLength).toString("utf8");
        cursor += CENTRAL_HEADER_BYTES + nameLength + extraLength + commentLength;

        if (localAt + LOCAL_HEADER_BYTES > archive.length || archive.readUInt32LE(localAt) !== LOCAL_HEADER_SIGNATURE) {
            throw new ZipFormatError(`The entry ${name} is damaged.`);
        }
        const dataAt = localAt + LOCAL_HEADER_BYTES + archive.readUInt16LE(localAt + 26) + archive.readUInt16LE(localAt + 28);
        let data: Buffer = archive.subarray(dataAt, dataAt + packedSize);

        if (flags & FLAG_ENCRYPTED) {
            if (password === undefined) throw new ZipFormatError(`The entry ${name} is locked.`);
            const keys = new ZipCryptoKeys(password);
            const plain = Buffer.alloc(data.length);
            data.forEach((byte, position) => {
                plain[position] = byte ^ keys.streamByte();
                keys.update(plain[position] ?? 0);
            });
            data = plain.subarray(ENCRYPTION_HEADER_BYTES);
        }
        const content = method === METHOD_DEFLATED ? inflateRawSync(data) : method === METHOD_STORED ? data : null;
        if (content === null) throw new ZipFormatError(`The entry ${name} uses a compression this tool does not read.`);
        if (content.length !== size || crc32(content) !== crc) {
            throw new ZipFormatError(flags & FLAG_ENCRYPTED ? `The entry ${name} does not open with this password.` : `The entry ${name} is damaged.`);
        }
        if (!name.endsWith("/")) entries.set(name, Buffer.from(content));
    }
    return entries;
}
