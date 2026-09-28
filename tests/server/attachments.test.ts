import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, readFile, readdir, rm } from "node:fs/promises";
import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { AttachmentKind, AttachmentUsage, SAMPLE_ZIP_PASSWORD, supportsAttachments } from "../../src/core/attachments.js";
import { NodeKind, Permission } from "../../src/core/enums.js";
import { NotFoundError } from "../../src/core/errors.js";
import type { Incident, RecordId } from "../../src/core/models.js";
import {
    AttachmentAwareService,
    AttachmentStore,
    HttpStatus,
    cleanFileName,
    createAttachmentHandler,
    createTimelineServer,
    openSqliteStore,
    recognise
} from "../../src/server/index.js";
import { ZipCryptoKeys, readZip } from "../../src/server/zip.js";
import { HttpTimelineApi } from "../../src/storage/http-api.js";

const LOCALHOST = "127.0.0.1";
const SMALL_LIMIT = 4096;
const READ_ONLY_HEADER = "x-read-only";
const PNG = Buffer.from("89504e470d0a1a0a0000000d4948445200000001000000010806000000", "hex");
const SAMPLE = Buffer.from("MZ\u0090\u0000This program cannot be run in DOS mode. Test sample.", "latin1");
const DISGUISED_SVG = Buffer.from("<svg xmlns=\"http://www.w3.org/2000/svg\" onload=\"alert(1)\"/>");
const TIMESTAMP = "2026-01-12T08:00:00";

function sha256(content: Buffer): string {
    return createHash("sha256").update(content).digest("hex");
}

function fileOf(content: Buffer): Blob {
    return new Blob([new Uint8Array(content)]);
}

/** Opens the one entry of a locked ZIP with a password, as an archive tool does. */
function unlockZip(zip: Buffer, password: string): Buffer {
    const nameLength = zip.readUInt16LE(26);
    const sealed = zip.subarray(30 + nameLength, 30 + nameLength + zip.readUInt32LE(18));
    const keys = new ZipCryptoKeys(password);
    const plain = Buffer.alloc(sealed.length);
    sealed.forEach((byte, index) => {
        plain[index] = byte ^ keys.streamByte();
        keys.update(plain[index] ?? 0);
    });
    return plain.subarray(12);
}

describe("evidence files", () => {
    let folder: string;
    let server: Server;
    let origin: string;
    let service: AttachmentAwareService;
    let api: HttpTimelineApi;
    let incident: Incident;
    let firstStep: RecordId;
    let secondStep: RecordId;

    before(async () => {
        folder = await mkdtemp(join(tmpdir(), "tlg-files-"));
        const { driver, store } = await openSqliteStore(":memory:");
        const attachments = await AttachmentStore.open(driver, store.tables, folder);
        service = new AttachmentAwareService(store, attachments);
        const authorize = (request: { headers: Record<string, unknown> }, permission: Permission): boolean => !(request.headers[READ_ONLY_HEADER] && permission !== Permission.Read);
        server = createTimelineServer({
            api: service,
            authorize,
            handlers: [createAttachmentHandler({ store: attachments, service, authorize, maxBytes: SMALL_LIMIT, onError: () => undefined })],
            onError: () => undefined
        });
        await new Promise<void>(resolve => server.listen(0, LOCALHOST, resolve));
        const address: AddressInfo | string | null = server.address();
        if (address === null || typeof address === "string") throw new Error("The test server has no port.");
        origin = `http://${LOCALHOST}:${address.port}`;
        api = new HttpTimelineApi({ baseUrl: `${origin}/api` });

        incident = await service.createIncident({ title: "Files" });
        firstStep = (await service.createStep(incident.id, { title: "Dropper written", timestamp: TIMESTAMP })).id;
        secondStep = (await service.createStep(incident.id, { title: "Dropper run", timestamp: TIMESTAMP })).id;
    });

    after(async () => {
        await new Promise<void>(resolve => server.close(() => resolve()));
        await rm(folder, { recursive: true, force: true });
    });

    it("tells images from anything else by their content, and keeps names to a plain file name", () => {
        assert.deepEqual(recognise(PNG), { kind: AttachmentKind.Image, mediaType: "image/png" });
        assert.equal(recognise(SAMPLE).kind, AttachmentKind.Sample);
        assert.equal(recognise(DISGUISED_SVG).kind, AttachmentKind.Sample);
        assert.equal(cleanFileName("../../etc/evil.exe"), "evil.exe");
        assert.equal(cleanFileName("C:\\Users\\x\\capture.png"), "capture.png");
        assert.equal(cleanFileName("\u0000\u001f"), "file");
    });

    it("keeps a file once, with its hashes, and ties it to several steps", async () => {
        assert.ok(supportsAttachments(api));
        const sample = await api.uploadAttachment(incident.id, fileOf(SAMPLE), "dropper.exe");
        assert.equal(sample.kind, AttachmentKind.Sample);
        assert.equal(sample.sha256, sha256(SAMPLE));
        assert.equal(sample.md5, createHash("md5").update(SAMPLE).digest("hex"));
        assert.equal((await api.uploadAttachment(incident.id, fileOf(SAMPLE), "renamed.exe")).id, sample.id);

        await api.linkAttachment(incident.id, firstStep, sample.id);
        await api.linkAttachment(incident.id, secondStep, sample.id);
        const [listed] = (await api.getDiagram(incident.id)).attachments ?? [];
        assert.equal(listed?.fileName, "dropper.exe");
        assert.deepEqual(listed?.stepIds, [firstStep, secondStep]);

        await api.unlinkAttachment(incident.id, secondStep, sample.id);
        assert.deepEqual((await api.listAttachments(incident.id))[0]?.stepIds, [firstStep]);
    });

    it("hands a sample out only inside a ZIP locked with the password, and never shows it", async () => {
        const sample = await api.uploadAttachment(incident.id, fileOf(SAMPLE), "dropper.exe");
        const download = await fetch(api.attachmentUrl(incident.id, sample.id, AttachmentUsage.Download));
        assert.equal(download.headers.get("content-type"), "application/zip");
        assert.match(download.headers.get("content-disposition") ?? "", /^attachment;.*dropper\.exe\.zip/);
        assert.match(download.headers.get("content-security-policy") ?? "", /sandbox/);
        assert.deepEqual(unlockZip(Buffer.from(await download.arrayBuffer()), SAMPLE_ZIP_PASSWORD), SAMPLE);

        const preview = await fetch(api.attachmentUrl(incident.id, sample.id, AttachmentUsage.Preview));
        assert.equal(preview.status, HttpStatus.BadRequest);
    });

    it("shows an image inline, in a sandbox", async () => {
        const image = await api.uploadAttachment(incident.id, fileOf(PNG), "capture.png");
        const preview = await fetch(api.attachmentUrl(incident.id, image.id, AttachmentUsage.Preview));
        assert.equal(preview.headers.get("content-type"), "image/png");
        assert.match(preview.headers.get("content-disposition") ?? "", /^inline/);
        assert.equal(preview.headers.get("x-content-type-options"), "nosniff");
        assert.deepEqual(Buffer.from(await preview.arrayBuffer()), PNG);
    });

    it("stores nothing in the clear", async () => {
        const stored = (await readdir(folder)).filter(name => /^[0-9a-f]{64}$/.test(name));
        assert.ok(stored.includes(sha256(SAMPLE)));
        for (const name of stored) {
            const bytes = await readFile(join(folder, name));
            assert.equal(bytes.indexOf(Buffer.from("cannot be run in DOS mode")), -1, `${name} is stored in the clear`);
        }
    });

    it("refuses to reach a file or a step through another incident", async () => {
        const other = await service.createIncident({ title: "Other" });
        const [file] = await api.listAttachments(incident.id);
        assert.ok(file);
        await assert.rejects(api.linkAttachment(other.id, firstStep, file.id), NotFoundError);
        await assert.rejects(api.linkAttachment(incident.id, firstStep, file.id + 1000), NotFoundError);
        const download = await fetch(api.attachmentUrl(other.id, file.id, AttachmentUsage.Download));
        assert.equal(download.status, HttpStatus.NotFound);
    });

    it("refuses files over the limit, raw bodies of another type and what the authorizer refuses", async () => {
        await assert.rejects(api.uploadAttachment(incident.id, fileOf(Buffer.alloc(SMALL_LIMIT + 1, 1)), "big.bin"));
        const wrongType = await fetch(`${origin}/api/incidents/${incident.id}/attachments`, { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
        assert.equal(wrongType.status, HttpStatus.UnsupportedMediaType);
        const readOnly = await fetch(`${origin}/api/incidents/${incident.id}/attachments`, { method: "POST", headers: { "Content-Type": "application/octet-stream", [READ_ONLY_HEADER]: "1" }, body: new Uint8Array(PNG) });
        assert.equal(readOnly.status, HttpStatus.Forbidden);
    });

    it("unties files from a deleted step, and clears the files of a deleted incident", async () => {
        const doomed = await service.createIncident({ title: "Doomed" });
        const step = await service.createStep(doomed.id, { title: "Only step", timestamp: TIMESTAMP });
        const unique = Buffer.concat([SAMPLE, Buffer.from("only in the doomed incident")]);
        const file = await api.uploadAttachment(doomed.id, fileOf(unique), "unique.exe");
        await api.linkAttachment(doomed.id, step.id, file.id);

        await service.deleteStep(doomed.id, step.id);
        assert.deepEqual((await api.listAttachments(doomed.id))[0]?.stepIds, []);

        await service.deleteIncident(doomed.id);
        assert.ok(!(await readdir(folder)).includes(sha256(unique)), "The file of the deleted incident is still on disk");
        assert.ok((await readdir(folder)).includes(sha256(SAMPLE)), "A file another incident uses was removed");
    });

    it("keeps a file as the content of a File record, until the record is deleted", async () => {
        const record = await service.createNode(incident.id, { name: "dropper", kind: NodeKind.File });
        const [file] = await api.listAttachments(incident.id);
        assert.ok(file);
        await api.linkNodeAttachment(incident.id, record.id, file.id);
        assert.deepEqual((await api.listAttachments(incident.id)).find(entry => entry.id === file.id)?.nodeIds, [record.id]);
        await service.deleteNode(incident.id, record.id);
        assert.deepEqual((await api.listAttachments(incident.id)).find(entry => entry.id === file.id)?.nodeIds, []);
    });

    it("carries an incident with its files in a bundle, samples locked one by one, and ties them back on import", async () => {
        const record = await service.createNode(incident.id, { name: "dropper", kind: NodeKind.File });
        const sample = await api.uploadAttachment(incident.id, fileOf(SAMPLE), "dropper.exe");
        await api.linkAttachment(incident.id, firstStep, sample.id);
        await api.linkNodeAttachment(incident.id, record.id, sample.id);

        const response = await fetch(api.bundleUrl(incident.id));
        assert.equal(response.headers.get("content-type"), "application/zip");
        const bundle = Buffer.from(await response.arrayBuffer());
        assert.equal(bundle.indexOf(SAMPLE.subarray(0, 24)), -1, "A sample shows in the clear in the bundle");
        const entries = readZip(bundle);
        assert.ok(entries.has("timeline.json") && entries.has("files.json") && entries.has("README.txt"));
        const locked = entries.get(`files/samples/${sha256(SAMPLE)}.zip`);
        assert.ok(locked, "The sample is missing from the bundle");
        assert.deepEqual(unlockZip(locked, SAMPLE_ZIP_PASSWORD), SAMPLE);

        const report = await api.importBundle(new Blob([new Uint8Array(bundle)]));
        assert.notEqual(report.incidentId, incident.id);
        const copy = await api.getDiagram(report.incidentId);
        const copied = copy.attachments?.find(entry => entry.sha256 === sha256(SAMPLE));
        assert.ok(copied, "The sample did not come back");
        assert.deepEqual(copied.stepIds.map(id => copy.steps.find(step => step.id === id)?.title), ["Dropper written"]);
        assert.deepEqual(copied.nodeIds.map(id => copy.nodes.find(node => node.id === id)?.name), ["dropper"]);
    });

    it("refuses a damaged bundle, and one whose file does not match its hash", async () => {
        await assert.rejects(api.importBundle(new Blob(["not a zip"])));
        const bundle = Buffer.from(await (await fetch(api.bundleUrl(incident.id))).arrayBuffer());
        const entries = readZip(bundle);
        const imagePath = [...entries.keys()].find(name => name.startsWith("files/images/"));
        assert.ok(imagePath);
        const { zipArchive } = await import("../../src/server/zip.js");
        const tampered = zipArchive([...entries].map(([name, content]) => ({ name, content: name === imagePath ? Buffer.concat([content, Buffer.from("x")]) : content })));
        await assert.rejects(api.importBundle(new Blob([new Uint8Array(tampered)])));
    });
});
