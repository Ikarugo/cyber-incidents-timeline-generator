// A bundle carries an incident to another instance or to someone else with its evidence: the timeline as the
// usual document, the files beside it, and a list tying each file to the records it belonged to. Pictures
// travel as they are; every other file sits in its own ZIP locked with the usual password, so unpacking the
// bundle never leaves a live sample on a disk.

import { createHash } from "node:crypto";
import { AttachmentKind, SAMPLE_ZIP_PASSWORD } from "../core/attachments.js";
import { documentKeys, exportDocument, type DocumentKey, type ImportReport } from "../core/document.js";
import { ValidationError } from "../core/errors.js";
import type { RecordId } from "../core/models.js";
import type { AttachmentAwareService, AttachmentStore } from "./attachments.js";
import { lockedZip, readZip, zipArchive, type ZipEntry } from "./zip.js";

export const BUNDLE_FORMAT = "cyber-incident-timeline-bundle";
const BUNDLE_VERSION = 1;
const TIMELINE_ENTRY = "timeline.json";
const MANIFEST_ENTRY = "files.json";
const README_ENTRY = "README.txt";
const IMAGE_FOLDER = "files/images/";
const SAMPLE_FOLDER = "files/samples/";
const SHA256 = /^[0-9a-f]{64}$/;

interface BundleFile {
    path: string;
    fileName: string;
    kind: AttachmentKind;
    sha256: string;
    sha1: string;
    md5: string;
    size: number;
    steps: DocumentKey[];
    nodes: DocumentKey[];
}

interface BundleManifest {
    format: typeof BUNDLE_FORMAT;
    version: number;
    files: BundleFile[];
}

const README = `This bundle holds an incident timeline and its evidence files.

timeline.json   the timeline, readable by any instance of cyber-incidents-timeline-generator
files.json      each file with its hashes and the steps and records it belongs to
files/images/   pictures, as they were attached
files/samples/  every other file, each inside its own ZIP locked with the password "${SAMPLE_ZIP_PASSWORD}"

The samples are handled as hostile. Open them only where analysing malware is safe.
`;

/** Writes the incident with its files as one ZIP. */
export async function exportBundle(service: AttachmentAwareService, files: AttachmentStore, incidentId: RecordId): Promise<Buffer> {
    const diagram = await service.getDiagram(incidentId);
    const keys = documentKeys(diagram);
    const entries: ZipEntry[] = [];
    const manifest: BundleManifest = { format: BUNDLE_FORMAT, version: BUNDLE_VERSION, files: [] };

    for (const attachment of diagram.attachments ?? []) {
        const { content } = await files.read(incidentId, attachment.id);
        const isImage = attachment.kind === AttachmentKind.Image;
        const path = isImage ? `${IMAGE_FOLDER}${attachment.sha256}-${attachment.fileName}` : `${SAMPLE_FOLDER}${attachment.sha256}.zip`;
        entries.push({ name: path, content: isImage ? content : lockedZip(attachment.fileName, content, SAMPLE_ZIP_PASSWORD) });
        manifest.files.push({
            path,
            fileName: attachment.fileName,
            kind: attachment.kind,
            sha256: attachment.sha256,
            sha1: attachment.sha1,
            md5: attachment.md5,
            size: attachment.size,
            steps: attachment.stepIds.flatMap(id => keys.steps.get(id) ?? []),
            nodes: attachment.nodeIds.flatMap(id => keys.nodes.get(id) ?? [])
        });
    }

    return zipArchive([
        { name: README_ENTRY, content: Buffer.from(README), compress: true },
        { name: TIMELINE_ENTRY, content: Buffer.from(JSON.stringify(exportDocument(diagram), null, 2)), compress: true },
        { name: MANIFEST_ENTRY, content: Buffer.from(JSON.stringify(manifest, null, 2)), compress: true },
        ...entries
    ]);
}

function parseJson(entries: ReadonlyMap<string, Buffer>, name: string): unknown {
    const entry = entries.get(name);
    if (!entry) throw new ValidationError([{ field: "bundle", message: `has no ${name}` }]);
    try {
        const parsed: unknown = JSON.parse(entry.toString("utf8"));
        return parsed;
    } catch {
        throw new ValidationError([{ field: "bundle", message: `holds a ${name} that is not JSON` }]);
    }
}

function readManifest(value: unknown): BundleFile[] {
    if (typeof value !== "object" || value === null || !("format" in value) || value.format !== BUNDLE_FORMAT || !("files" in value) || !Array.isArray(value.files)) {
        throw new ValidationError([{ field: "bundle", message: "is not a timeline bundle" }]);
    }
    return value.files.map((raw: unknown, index: number): BundleFile => {
        const file = typeof raw === "object" && raw !== null ? raw as Partial<Record<keyof BundleFile, unknown>> : {};
        const text = (field: keyof BundleFile): string => {
            const found = file[field];
            if (typeof found !== "string") throw new ValidationError([{ field: `files[${index}].${field}`, message: "is missing" }]);
            return found;
        };
        const keys = (field: "steps" | "nodes"): DocumentKey[] => {
            const found = file[field];
            return Array.isArray(found) ? found.filter((key): key is string => typeof key === "string") : [];
        };
        const sha256 = text("sha256");
        if (!SHA256.test(sha256)) throw new ValidationError([{ field: `files[${index}].sha256`, message: "is not a SHA-256" }]);
        return {
            path: text("path"), fileName: text("fileName"), kind: text("kind") === AttachmentKind.Image ? AttachmentKind.Image : AttachmentKind.Sample,
            sha256, sha1: text("sha1"), md5: text("md5"), size: typeof file.size === "number" ? file.size : 0, steps: keys("steps"), nodes: keys("nodes")
        };
    });
}

function contentOf(entries: ReadonlyMap<string, Buffer>, file: BundleFile): Buffer {
    const packed = entries.get(file.path);
    if (!packed) throw new ValidationError([{ field: "bundle", message: `lacks ${file.path}` }]);
    if (file.path.startsWith(IMAGE_FOLDER)) return packed;
    const [content] = readZip(packed, SAMPLE_ZIP_PASSWORD).values();
    if (!content) throw new ValidationError([{ field: "bundle", message: `holds an empty ${file.path}` }]);
    return content;
}

/**
 * Imports the timeline of a bundle, into the incident given or a new one, then keeps its files and ties them
 * back. Every file is checked against the hash the bundle lists before anything is imported.
 */
export async function importBundle(service: AttachmentAwareService, files: AttachmentStore, bundle: Buffer, into?: RecordId): Promise<ImportReport> {
    const entries = readZip(bundle);
    const document = parseJson(entries, TIMELINE_ENTRY);
    const listed = readManifest(parseJson(entries, MANIFEST_ENTRY));
    const contents = listed.map(file => ({ file, content: contentOf(entries, file) }));
    for (const { file, content } of contents) {
        if (createHash("sha256").update(content).digest("hex") !== file.sha256) {
            throw new ValidationError([{ field: "bundle", message: `holds a ${file.fileName} that does not match its hash` }]);
        }
    }

    const report = await service.importDocument(document, into === undefined ? {} : { into });
    for (const { file, content } of contents) {
        const kept = await files.add(report.incidentId, file.fileName, content);
        for (const key of file.steps) {
            const stepId = report.keys.steps[key];
            if (stepId !== undefined) await files.link(report.incidentId, stepId, kept.id);
        }
        for (const key of file.nodes) {
            const nodeId = report.keys.nodes[key];
            if (nodeId !== undefined) await files.linkNode(report.incidentId, nodeId, kept.id);
        }
    }
    return report;
}
