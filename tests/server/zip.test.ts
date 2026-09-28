import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { describe, it } from "node:test";
import { ZipCryptoKeys, ZipFormatError, crc32, lockedZip, readZip, zipArchive } from "../../src/server/zip.js";

const PASSWORD = "infected";
const ENCRYPTION_HEADER_BYTES = 12;
const LOCAL_HEADER_BYTES = 30;

/** Reads back the one entry of a locked ZIP, the way an archive tool does. */
function unlock(zip: Buffer, password: string): { name: string; content: Buffer; passwordAccepted: boolean } {
    assert.equal(zip.readUInt32LE(0), 0x04034b50);
    assert.equal(zip.readUInt16LE(6) & 1, 1, "The entry is not encrypted");
    const crc = zip.readUInt32LE(14);
    const sealedSize = zip.readUInt32LE(18);
    const nameLength = zip.readUInt16LE(26);
    const name = zip.subarray(LOCAL_HEADER_BYTES, LOCAL_HEADER_BYTES + nameLength).toString("utf8");
    const sealed = zip.subarray(LOCAL_HEADER_BYTES + nameLength, LOCAL_HEADER_BYTES + nameLength + sealedSize);

    const keys = new ZipCryptoKeys(password);
    const plain = Buffer.alloc(sealed.length);
    sealed.forEach((byte, index) => {
        plain[index] = byte ^ keys.streamByte();
        keys.update(plain[index] ?? 0);
    });
    return {
        name,
        content: plain.subarray(ENCRYPTION_HEADER_BYTES),
        passwordAccepted: plain[ENCRYPTION_HEADER_BYTES - 1] === crc >>> 24
    };
}

describe("locked ZIP", () => {
    it("computes the CRC every archive tool checks", () => {
        assert.equal(crc32(Buffer.from("123456789")), 0xcbf43926);
    });

    it("gives the file back unchanged with the password, under its own name", () => {
        const content = randomBytes(5000);
        const opened = unlock(lockedZip("dropper été.exe", content, PASSWORD), PASSWORD);
        assert.equal(opened.name, "dropper été.exe");
        assert.ok(opened.passwordAccepted);
        assert.deepEqual(opened.content, content);
    });

    it("hides the content and turns a wrong password away", () => {
        const content = Buffer.from("This program cannot be run in DOS mode.".repeat(20));
        const zip = lockedZip("sample.exe", content, PASSWORD);
        assert.equal(zip.indexOf(content.subarray(0, 24)), -1, "The content shows through the archive");
        const wrong = unlock(zip, "not the password");
        assert.notDeepEqual(wrong.content, content);
    });

    it("reads back an archive of stored, compressed and locked entries", () => {
        const text = Buffer.from("timeline ".repeat(500));
        const sample = randomBytes(3000);
        const archive = zipArchive([{ name: "timeline.json", content: text, compress: true }, { name: "files/sample.bin", content: sample, password: PASSWORD }]);
        assert.ok(archive.length < text.length, "The text was not compressed");
        const entries = readZip(archive, PASSWORD);
        assert.deepEqual(entries.get("timeline.json"), text);
        assert.deepEqual(entries.get("files/sample.bin"), sample);
        assert.throws(() => readZip(archive, "wrong"), ZipFormatError);
        assert.throws(() => readZip(archive), ZipFormatError);
        assert.throws(() => readZip(Buffer.from("not an archive")), ZipFormatError);
    });
});
