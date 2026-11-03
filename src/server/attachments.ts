// Evidence files of the reference server. The bytes live in a folder beside the database, named by their
// SHA-256 and enciphered with a key kept in that folder: the point is not secrecy, the key sits right there,
// but that no antivirus on the host quarantines a sample and no one opens one from the disk by mistake.

import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";
import { mkdir, readFile, readdir, rename, rm, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { AttachmentKind, type Attachment } from "../core/attachments.js";
import { NotFoundError, ValidationError } from "../core/errors.js";
import type { Diagram, RecordId } from "../core/models.js";
import { TimelineService, type TimelineServiceOptions } from "../core/service.js";
import type { TimelineStore } from "../core/store.js";
import { formatWallClock } from "../core/time.js";
import { RowReader, type SqlRow } from "./sql/driver.js";
import { sqliteAttachmentSchema, type TableNames } from "./sql/schema.js";
import type { SqliteDriver } from "./sql/sqlite-driver.js";

const KEY_FILE = ".key";
const KEY_BYTES = 32;
const IV_BYTES = 16;
const CIPHER = "aes-256-ctr";
const OWNER_ONLY = 0o600;
const STORED_NAME = /^[0-9a-f]{64}$/;
const MAX_FILE_NAME_LENGTH = 200;
const FALLBACK_FILE_NAME = "file";

interface ImageSignature {
    mediaType: string;
    matches(bytes: Uint8Array): boolean;
}

function startsWith(bytes: Uint8Array, prefix: readonly number[], offset = 0): boolean {
    return prefix.every((value, index) => bytes[offset + index] === value);
}

function ascii(text: string): number[] {
    return [...text].map(character => character.charCodeAt(0));
}

// Only raster formats: an SVG is a document that can carry script, so it is handled as a sample
const IMAGE_SIGNATURES: readonly ImageSignature[] = [
    { mediaType: "image/png", matches: bytes => startsWith(bytes, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
    { mediaType: "image/jpeg", matches: bytes => startsWith(bytes, [0xff, 0xd8, 0xff]) },
    { mediaType: "image/gif", matches: bytes => startsWith(bytes, ascii("GIF87a")) || startsWith(bytes, ascii("GIF89a")) },
    { mediaType: "image/webp", matches: bytes => startsWith(bytes, ascii("RIFF")) && startsWith(bytes, ascii("WEBP"), 8) }
];

/** What the content is, whatever its name claims. */
export function recognise(bytes: Uint8Array): { kind: AttachmentKind; mediaType: string | null } {
    const image = IMAGE_SIGNATURES.find(signature => signature.matches(bytes));
    return image ? { kind: AttachmentKind.Image, mediaType: image.mediaType } : { kind: AttachmentKind.Sample, mediaType: null };
}

/**
 * The name as the uploader's machine had it, without any folder, control character or path trick, since
 * it travels back in headers and inside ZIPs.
 */
export function cleanFileName(name: string | null | undefined): string {
    const base = (name ?? "").split(/[\\/]/).pop() ?? "";
    const printable = base.replace(/[\u0000-\u001f\u007f]/g, "").trim().replace(/^\.+/, "");
    return printable.slice(0, MAX_FILE_NAME_LENGTH) || FALLBACK_FILE_NAME;
}

function digest(algorithm: string, bytes: Uint8Array): string {
    return createHash(algorithm).update(bytes).digest("hex");
}

export interface StoredAttachment {
    attachment: Attachment;
    content: Buffer;
}

export class AttachmentStore {
    private readonly driver: SqliteDriver;
    private readonly tables: TableNames;
    private readonly directory: string;
    private readonly key: Buffer;

    private constructor(driver: SqliteDriver, tables: TableNames, directory: string, key: Buffer) {
        this.driver = driver;
        this.tables = tables;
        this.directory = directory;
        this.key = key;
    }

    /** Creates the tables and the folder when they are missing, and the key the first time. */
    static async open(driver: SqliteDriver, tables: TableNames, directory: string): Promise<AttachmentStore> {
        await driver.executeScript(sqliteAttachmentSchema(tables));
        await mkdir(directory, { recursive: true });
        const keyPath = join(directory, KEY_FILE);
        let key: Buffer;
        try {
            key = await readFile(keyPath);
        } catch {
            key = randomBytes(KEY_BYTES);
            await writeFile(keyPath, key, { mode: OWNER_ONLY, flag: "wx" });
        }
        if (key.length !== KEY_BYTES) {
            throw new Error(`${keyPath} is not a key written by this tool.`);
        }
        const store = new AttachmentStore(driver, tables, directory, key);
        await store.sweep();
        return store;
    }

    private async requireIncident(incidentId: RecordId): Promise<void> {
        const rows = await this.driver.query(`SELECT id FROM ${this.tables.incidents} WHERE id = ?`, [incidentId]);
        if (rows.length === 0) throw new NotFoundError(`Incident ${incidentId} does not exist.`);
    }

    private async requireStep(incidentId: RecordId, stepId: RecordId): Promise<void> {
        const rows = await this.driver.query(`SELECT id FROM ${this.tables.steps} WHERE id = ? AND incident_id = ?`, [stepId, incidentId]);
        if (rows.length === 0) throw new NotFoundError(`Step ${stepId} does not exist in incident ${incidentId}.`);
    }

    private async requireNode(incidentId: RecordId, nodeId: RecordId): Promise<void> {
        const rows = await this.driver.query(`SELECT id FROM ${this.tables.nodes} WHERE id = ? AND incident_id = ?`, [nodeId, incidentId]);
        if (rows.length === 0) throw new NotFoundError(`Record ${nodeId} does not exist in incident ${incidentId}.`);
    }

    private async tiesOf(table: string, column: string, incidentId: RecordId): Promise<Map<RecordId, RecordId[]>> {
        const rows = await this.driver.query(
            `SELECT l.${column} AS record_id, l.attachment_id FROM ${table} l JOIN ${this.tables.attachments} a ON a.id = l.attachment_id WHERE a.incident_id = ? ORDER BY l.${column}`,
            [incidentId]
        );
        const tied = new Map<RecordId, RecordId[]>();
        for (const row of rows) {
            const read = new RowReader(row);
            const attachmentId = read.number("attachment_id");
            tied.set(attachmentId, [...(tied.get(attachmentId) ?? []), read.number("record_id")]);
        }
        return tied;
    }

    private toAttachment(row: SqlRow, stepIds: RecordId[], nodeIds: RecordId[]): Attachment {
        const read = new RowReader(row);
        return {
            id: read.number("id"),
            incidentId: read.number("incident_id"),
            fileName: read.text("file_name"),
            size: read.number("size"),
            kind: read.text("kind") === AttachmentKind.Image ? AttachmentKind.Image : AttachmentKind.Sample,
            mediaType: read.nullableText("media_type"),
            md5: read.text("md5"),
            sha1: read.text("sha1"),
            sha256: read.text("sha256"),
            uploadedAt: read.text("uploaded_at"),
            stepIds,
            nodeIds
        };
    }

    async list(incidentId: RecordId): Promise<Attachment[]> {
        const rows = await this.driver.query(`SELECT * FROM ${this.tables.attachments} WHERE incident_id = ? ORDER BY id`, [incidentId]);
        const stepsOf = await this.tiesOf(this.tables.stepAttachments, "step_id", incidentId);
        const nodesOf = await this.tiesOf(this.tables.nodeAttachments, "node_id", incidentId);
        return rows.map(row => {
            const id = new RowReader(row).number("id");
            return this.toAttachment(row, stepsOf.get(id) ?? [], nodesOf.get(id) ?? []);
        });
    }

    async get(incidentId: RecordId, attachmentId: RecordId): Promise<Attachment> {
        const found = (await this.list(incidentId)).find(entry => entry.id === attachmentId);
        if (!found) throw new NotFoundError(`File ${attachmentId} does not exist in incident ${incidentId}.`);
        return found;
    }

    /**
     * Keeps a file for the incident. The same content sent twice to one incident is kept once, under the
     * name it first came with, and a content shared by incidents is stored once on disk.
     */
    async add(incidentId: RecordId, fileName: string, content: Buffer): Promise<Attachment> {
        await this.requireIncident(incidentId);
        if (content.length === 0) {
            throw new ValidationError([{ field: "file", message: "is empty" }]);
        }

        const sha256 = digest("sha256", content);
        const { kind, mediaType } = recognise(content);
        await this.writeContent(sha256, content);
        await this.driver.execute(
            `INSERT OR IGNORE INTO ${this.tables.attachments} (incident_id, file_name, size, kind, media_type, md5, sha1, sha256, uploaded_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
            [incidentId, cleanFileName(fileName), content.length, kind, mediaType, digest("md5", content), digest("sha1", content), sha256, formatWallClock(new Date())]
        );
        const rows = await this.driver.query(`SELECT id FROM ${this.tables.attachments} WHERE incident_id = ? AND sha256 = ?`, [incidentId, sha256]);
        const [row] = rows;
        if (!row) throw new Error("The file was not recorded.");
        return this.get(incidentId, new RowReader(row).number("id"));
    }

    async link(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        await this.requireStep(incidentId, stepId);
        await this.get(incidentId, attachmentId);
        await this.driver.execute(`INSERT OR IGNORE INTO ${this.tables.stepAttachments} (step_id, attachment_id) VALUES (?, ?)`, [stepId, attachmentId]);
    }

    async unlink(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        await this.requireStep(incidentId, stepId);
        await this.get(incidentId, attachmentId);
        await this.driver.execute(`DELETE FROM ${this.tables.stepAttachments} WHERE step_id = ? AND attachment_id = ?`, [stepId, attachmentId]);
    }

    async linkNode(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        await this.requireNode(incidentId, nodeId);
        await this.get(incidentId, attachmentId);
        await this.driver.execute(`INSERT OR IGNORE INTO ${this.tables.nodeAttachments} (node_id, attachment_id) VALUES (?, ?)`, [nodeId, attachmentId]);
    }

    async unlinkNode(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        await this.requireNode(incidentId, nodeId);
        await this.get(incidentId, attachmentId);
        await this.driver.execute(`DELETE FROM ${this.tables.nodeAttachments} WHERE node_id = ? AND attachment_id = ?`, [nodeId, attachmentId]);
    }

    async remove(incidentId: RecordId, attachmentId: RecordId): Promise<void> {
        const attachment = await this.get(incidentId, attachmentId);
        await this.driver.execute(`DELETE FROM ${this.tables.attachments} WHERE id = ?`, [attachmentId]);
        await this.forgetIfUnused(attachment.sha256);
    }

    /** The file and its content, checked against the hash it was stored under. */
    async read(incidentId: RecordId, attachmentId: RecordId): Promise<StoredAttachment> {
        const attachment = await this.get(incidentId, attachmentId);
        const stored = await readFile(join(this.directory, attachment.sha256));
        const decipher = createDecipheriv(CIPHER, this.key, stored.subarray(0, IV_BYTES));
        const content = Buffer.concat([decipher.update(stored.subarray(IV_BYTES)), decipher.final()]);
        if (digest("sha256", content) !== attachment.sha256) {
            throw new Error(`The stored copy of ${attachment.sha256} no longer matches its hash.`);
        }
        return { attachment, content };
    }

    private async writeContent(sha256: string, content: Buffer): Promise<void> {
        const target = join(this.directory, sha256);
        const iv = randomBytes(IV_BYTES);
        const cipher = createCipheriv(CIPHER, this.key, iv);
        const sealed = Buffer.concat([iv, cipher.update(content), cipher.final()]);
        // Written aside then renamed, so a crash never leaves half a file under a valid name
        const temporary = `${target}.${randomBytes(4).toString("hex")}.part`;
        await writeFile(temporary, sealed, { mode: OWNER_ONLY });
        await rename(temporary, target);
    }

    private async forgetIfUnused(sha256: string): Promise<void> {
        const rows = await this.driver.query(`SELECT 1 AS used FROM ${this.tables.attachments} WHERE sha256 = ? LIMIT 1`, [sha256]);
        if (rows.length === 0) await rm(join(this.directory, sha256), { force: true });
    }

    /** Deletes stored files no incident uses any more, such as those of a deleted incident. */
    async sweep(): Promise<void> {
        const used = new Set((await this.driver.query(`SELECT DISTINCT sha256 FROM ${this.tables.attachments}`)).map(row => new RowReader(row).text("sha256")));
        for (const entry of await readdir(this.directory)) {
            const leftover = entry.endsWith(".part");
            if (leftover || (STORED_NAME.test(entry) && !used.has(entry))) {
                await rm(join(this.directory, entry), { force: true });
            }
        }
    }
}

/**
 * The timeline service of a server that keeps files: the diagram carries them, which is also what lets the
 * workspace show files a colleague added, and deleting an incident clears the files only it used.
 */
export class AttachmentAwareService extends TimelineService {
    readonly attachments: AttachmentStore;

    constructor(store: TimelineStore, attachments: AttachmentStore, options: TimelineServiceOptions = {}) {
        super(store, options);
        this.attachments = attachments;
    }

    override async getDiagram(incidentId: RecordId): Promise<Diagram> {
        const diagram = await super.getDiagram(incidentId);
        return { ...diagram, attachments: await this.attachments.list(incidentId) };
    }

    override async deleteIncident(incidentId: RecordId): Promise<void> {
        await super.deleteIncident(incidentId);
        await this.attachments.sweep();
    }
}
