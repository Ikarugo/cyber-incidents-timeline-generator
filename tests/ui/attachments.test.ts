import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import { AttachmentKind, AttachmentUsage, type Attachment, type AttachmentApi } from "../../src/core/attachments.js";
import { NodeKind, RecordType } from "../../src/core/enums.js";
import type { ImportReport } from "../../src/core/document.js";
import type { Diagram, RecordId } from "../../src/core/models.js";
import { TimelineService } from "../../src/core/service.js";
import { MemoryTimelineStore } from "../../src/storage/memory-store.js";
import { BUILT_IN_RENDERERS } from "../../src/ui/renderers/index.js";
import { mountTimeline } from "../../src/ui/workspace.js";
import { chooseOption, installDom, syntheticEvent } from "../support/dom.js";
import { createIncident, createService } from "../support/fixtures.js";

const SETTLE_ROUNDS = 20;
const TIMESTAMP = "2026-01-12T08:00:00";
const PNG_START = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const EVIDENCE = ".tlg-evidence";
const ROW = ".tlg-evidence-row";

async function settle(): Promise<void> {
    for (let round = 0; round < SETTLE_ROUNDS; round += 1) {
        await new Promise(resolve => setTimeout(resolve, 0));
    }
}

function mountPoint(): HTMLElement {
    const element = document.createElement("div");
    document.body.appendChild(element);
    return element;
}

/** A service that keeps files in memory, the way the reference server does on disk. */
class FileKeepingService extends TimelineService implements AttachmentApi {
    private files: Attachment[] = [];

    override async getDiagram(incidentId: RecordId): Promise<Diagram> {
        return { ...(await super.getDiagram(incidentId)), attachments: await this.listAttachments(incidentId) };
    }

    async listAttachments(incidentId: RecordId): Promise<Attachment[]> {
        return this.files.filter(file => file.incidentId === incidentId).map(file => ({ ...file, stepIds: [...file.stepIds], nodeIds: [...file.nodeIds] }));
    }

    async uploadAttachment(incidentId: RecordId, file: Blob, fileName: string): Promise<Attachment> {
        const bytes = new Uint8Array(await file.arrayBuffer());
        const image = PNG_START.every((value, index) => bytes[index] === value);
        const attachment: Attachment = {
            id: this.files.length + 1, incidentId, fileName, size: bytes.length,
            kind: image ? AttachmentKind.Image : AttachmentKind.Sample, mediaType: image ? "image/png" : null,
            md5: "0".repeat(32), sha1: "0".repeat(40), sha256: String(this.files.length).padStart(64, "a"), uploadedAt: TIMESTAMP, stepIds: [], nodeIds: []
        };
        this.files.push(attachment);
        return attachment;
    }

    async linkAttachment(_incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        const file = this.files.find(entry => entry.id === attachmentId);
        if (file && !file.stepIds.includes(stepId)) file.stepIds.push(stepId);
    }

    async unlinkAttachment(_incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        const file = this.files.find(entry => entry.id === attachmentId);
        if (file) file.stepIds = file.stepIds.filter(id => id !== stepId);
    }

    async linkNodeAttachment(_incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        const file = this.files.find(entry => entry.id === attachmentId);
        if (file && !file.nodeIds.includes(nodeId)) file.nodeIds.push(nodeId);
    }

    async unlinkNodeAttachment(_incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        const file = this.files.find(entry => entry.id === attachmentId);
        if (file) file.nodeIds = file.nodeIds.filter(id => id !== nodeId);
    }

    importBundle(): Promise<ImportReport> {
        return Promise.reject(new Error("Bundles are read by the reference server."));
    }

    bundleUrl(incidentId: RecordId): string {
        return `/bundles/${incidentId}`;
    }

    async deleteAttachment(_incidentId: RecordId, attachmentId: RecordId): Promise<void> {
        this.files = this.files.filter(entry => entry.id !== attachmentId);
    }

    attachmentUrl(incidentId: RecordId, attachmentId: RecordId, usage: AttachmentUsage): string {
        return `/files/${incidentId}/${attachmentId}/${usage}`;
    }
}

function drop(target: Element, files: File[]): void {
    const event = syntheticEvent("drop");
    Object.defineProperty(event, "dataTransfer", { value: { files } });
    target.dispatchEvent(event);
}

describe("evidence files in the details panel", () => {
    before(() => {
        installDom();
    });

    it("offers nothing when the api keeps no files", async () => {
        const { service } = createService();
        const incident = await createIncident(service);
        const step = await service.createStep(incident.id, { title: "Beacon", timestamp: TIMESTAMP });
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });
        handle.select({ type: RecordType.Step, id: step.id });
        await settle();
        assert.equal(element.querySelector(EVIDENCE), null);
        handle.destroy();
    });

    it("attaches dropped files to the step, showing pictures and marking anything else as hostile", async () => {
        const service = new FileKeepingService(new MemoryTimelineStore());
        const incident = await createIncident(service);
        const step = await service.createStep(incident.id, { title: "Beacon", timestamp: TIMESTAMP });
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });
        handle.select({ type: RecordType.Step, id: step.id });
        await settle();
        const block = element.querySelector(EVIDENCE);
        assert.ok(block, "The details panel has no evidence files");

        drop(block, [new File([new Uint8Array(PNG_START)], "capture.png"), new File(["MZ sample"], "dropper.exe")]);
        await settle();
        const rows = [...element.querySelectorAll(ROW)];
        assert.equal(rows.length, 2);
        assert.equal(rows[0]?.querySelector("img")?.getAttribute("src"), "/files/1/1/preview");
        assert.ok(rows[1]?.classList.contains("is-sample"));
        assert.ok(rows[1]?.querySelector(".tlg-evidence-notice"), "The sample is not marked as hostile");
        assert.equal(rows[1]?.querySelector("a")?.getAttribute("href"), "/files/1/2/download");
        assert.deepEqual((await service.listAttachments(incident.id)).map(file => file.stepIds), [[step.id], [step.id]]);
        handle.destroy();
    });

    it("ties a file already in the incident to another step, and unties it", async () => {
        const service = new FileKeepingService(new MemoryTimelineStore());
        const incident = await createIncident(service);
        const first = await service.createStep(incident.id, { title: "Written", timestamp: TIMESTAMP });
        const second = await service.createStep(incident.id, { title: "Run", timestamp: TIMESTAMP });
        const file = await service.uploadAttachment(incident.id, new Blob(["MZ sample"]), "dropper.exe");
        await service.linkAttachment(incident.id, first.id, file.id);
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });

        handle.select({ type: RecordType.Step, id: second.id });
        await settle();
        const picker = element.querySelector<HTMLElement>(".tlg-evidence-controls .tlg-combo");
        assert.ok(picker, "Files of the incident are not offered");
        chooseOption(picker, "dropper.exe");
        await settle();
        assert.deepEqual((await service.listAttachments(incident.id))[0]?.stepIds, [first.id, second.id]);
        assert.match(element.querySelector(".tlg-evidence-meta")?.textContent ?? "", /Also proves 1 other step/);

        const untie = element.querySelector<HTMLButtonElement>(`${ROW} button[aria-label="Untie from this step"]`);
        assert.ok(untie);
        untie.dispatchEvent(syntheticEvent("click"));
        await settle();
        assert.deepEqual((await service.listAttachments(incident.id))[0]?.stepIds, [first.id]);
        assert.equal(element.querySelectorAll(ROW).length, 0);
        handle.destroy();
    });

    it("keeps the content of a File record, naming it after the file and identifying it by its hash", async () => {
        const service = new FileKeepingService(new MemoryTimelineStore());
        const incident = await createIncident(service);
        const kindLabel = (await service.getCatalog()).nodeKinds.find(entry => entry.kind === NodeKind.File)?.label ?? "File";
        const record = await service.createNode(incident.id, { name: kindLabel, kind: NodeKind.File });
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });
        handle.select({ type: RecordType.Node, id: record.id });
        await settle();
        const block = element.querySelector(EVIDENCE);
        assert.ok(block, "A File record offers no content");

        drop(block, [new File(["MZ sample"], "dropper.exe")]);
        await settle();
        const [file] = await service.listAttachments(incident.id);
        assert.deepEqual(file?.nodeIds, [record.id]);
        const updated = (await service.getDiagram(incident.id)).nodes.find(node => node.id === record.id);
        assert.equal(updated?.name, "dropper.exe");
        assert.equal(updated?.identifier, file?.sha256);
        assert.ok(element.querySelector(`${ROW}.is-sample`), "The content is not shown as hostile");
        handle.destroy();
    });

    it("leaves records of other kinds without content", async () => {
        const service = new FileKeepingService(new MemoryTimelineStore());
        const incident = await createIncident(service);
        const host = await service.createNode(incident.id, { name: "FIN-WS-042", kind: NodeKind.Workstation });
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });
        handle.select({ type: RecordType.Node, id: host.id });
        await settle();
        assert.equal(element.querySelector(EVIDENCE), null);
        handle.destroy();
    });

    it("marks a card with a paperclip and the number of files proving its step", async () => {
        const service = new FileKeepingService(new MemoryTimelineStore());
        const incident = await createIncident(service);
        const proven = await service.createStep(incident.id, { title: "Proven", timestamp: TIMESTAMP });
        await service.createStep(incident.id, { title: "Unproven", timestamp: "2026-01-12T09:00:00" });
        for (const name of ["one.png", "two.exe"]) {
            const file = await service.uploadAttachment(incident.id, new Blob([name]), name);
            await service.linkAttachment(incident.id, proven.id, file.id);
        }
        const element = mountPoint();
        const handle = await mountTimeline(element, { api: service, incidentId: incident.id, preferences: null, renderers: BUILT_IN_RENDERERS.slice(0, 1), syncInterval: null });
        await settle();
        const marks = [...element.querySelectorAll("[data-evidence]")];
        assert.deepEqual(marks.map(mark => mark.getAttribute("data-evidence")), ["2"]);
        handle.destroy();
    });
});
