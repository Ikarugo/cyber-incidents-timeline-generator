// A TimelineApi that hands out the catalog with a viewer's own words and icons, for a catalog the viewer does
// not own. Everything else passes straight through, so the owner still validates every write.

import { supportsAttachments, type Attachment, type AttachmentApi, type AttachmentUsage } from "../core/attachments.js";
import type { CatalogSettings, CatalogUsageEntry } from "../core/catalog-settings.js";
import type { Catalog } from "../core/catalog.js";
import type { ImportOptions, ImportReport, TimelineDocument } from "../core/document.js";
import type {
    Diagram, DiagramLink, DiagramNode, DiagramStep, Incident, IncidentCreateInput, IncidentUpdateInput, LayoutInput,
    LinkCreateInput, LinkUpdateInput, NodeCreateInput, NodeUpdateInput, RecordId, StepCreateInput, StepUpdateInput
} from "../core/models.js";
import type { TimelineApi } from "../core/service.js";
import type { DiagramSummary } from "../core/summary.js";
import { relabelCatalog, type AppSettings } from "./settings.js";

export class RelabeledTimelineApi implements TimelineApi {
    protected readonly api: TimelineApi;
    /** Read on every call, so saved settings apply to the next load without a new wrapper. */
    private readonly settings: () => AppSettings;

    constructor(api: TimelineApi, settings: () => AppSettings) {
        this.api = api;
        this.settings = settings;
    }

    async getCatalog(): Promise<Catalog> {
        return relabelCatalog(await this.api.getCatalog(), this.settings());
    }

    async getDiagram(incidentId: RecordId): Promise<Diagram> {
        const diagram = await this.api.getDiagram(incidentId);
        return { ...diagram, catalog: relabelCatalog(diagram.catalog, this.settings()) };
    }

    getCatalogSettings(): Promise<CatalogSettings> {
        return this.api.getCatalogSettings();
    }

    // Settings saved elsewhere come back relabeled like every catalog this wrapper hands out
    async saveCatalogSettings(settings: CatalogSettings): Promise<Catalog> {
        return relabelCatalog(await this.api.saveCatalogSettings(settings), this.settings());
    }

    catalogUsage(settings: CatalogSettings): Promise<CatalogUsageEntry[]> {
        return this.api.catalogUsage(settings);
    }

    listIncidents(): Promise<Incident[]> {
        return this.api.listIncidents();
    }

    getIncident(incidentId: RecordId): Promise<Incident> {
        return this.api.getIncident(incidentId);
    }

    createIncident(input: IncidentCreateInput): Promise<Incident> {
        return this.api.createIncident(input);
    }

    updateIncident(incidentId: RecordId, input: IncidentUpdateInput): Promise<void> {
        return this.api.updateIncident(incidentId, input);
    }

    deleteIncident(incidentId: RecordId): Promise<void> {
        return this.api.deleteIncident(incidentId);
    }

    getSummary(incidentId: RecordId): Promise<DiagramSummary> {
        return this.api.getSummary(incidentId);
    }

    exportDocument(incidentId: RecordId): Promise<TimelineDocument> {
        return this.api.exportDocument(incidentId);
    }

    importDocument(document: unknown, options?: ImportOptions & { into?: RecordId }): Promise<ImportReport> {
        return this.api.importDocument(document, options);
    }

    createNode(incidentId: RecordId, input: NodeCreateInput): Promise<DiagramNode> {
        return this.api.createNode(incidentId, input);
    }

    updateNode(incidentId: RecordId, nodeId: RecordId, input: NodeUpdateInput): Promise<void> {
        return this.api.updateNode(incidentId, nodeId, input);
    }

    deleteNode(incidentId: RecordId, nodeId: RecordId): Promise<void> {
        return this.api.deleteNode(incidentId, nodeId);
    }

    createStep(incidentId: RecordId, input: StepCreateInput): Promise<DiagramStep> {
        return this.api.createStep(incidentId, input);
    }

    updateStep(incidentId: RecordId, stepId: RecordId, input: StepUpdateInput): Promise<void> {
        return this.api.updateStep(incidentId, stepId, input);
    }

    deleteStep(incidentId: RecordId, stepId: RecordId): Promise<void> {
        return this.api.deleteStep(incidentId, stepId);
    }

    createLink(incidentId: RecordId, input: LinkCreateInput): Promise<DiagramLink> {
        return this.api.createLink(incidentId, input);
    }

    updateLink(incidentId: RecordId, linkId: RecordId, input: LinkUpdateInput): Promise<void> {
        return this.api.updateLink(incidentId, linkId, input);
    }

    deleteLink(incidentId: RecordId, linkId: RecordId): Promise<void> {
        return this.api.deleteLink(incidentId, linkId);
    }

    saveLayout(incidentId: RecordId, layouts: LayoutInput[]): Promise<void> {
        return this.api.saveLayout(incidentId, layouts);
    }

}

/**
 * The same wrapper for an api that keeps evidence files. It is a class of its own so a page whose api keeps
 * none does not look as though it does, which is what decides whether the files are offered at all.
 */
export class RelabeledAttachmentApi extends RelabeledTimelineApi implements AttachmentApi {
    private readonly attachments: AttachmentApi;

    constructor(api: TimelineApi & AttachmentApi, settings: () => AppSettings) {
        super(api, settings);
        this.attachments = api;
    }

    listAttachments(incidentId: RecordId): Promise<Attachment[]> {
        return this.attachments.listAttachments(incidentId);
    }

    uploadAttachment(incidentId: RecordId, file: Blob, fileName: string): Promise<Attachment> {
        return this.attachments.uploadAttachment(incidentId, file, fileName);
    }

    linkAttachment(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        return this.attachments.linkAttachment(incidentId, stepId, attachmentId);
    }

    unlinkAttachment(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void> {
        return this.attachments.unlinkAttachment(incidentId, stepId, attachmentId);
    }

    linkNodeAttachment(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        return this.attachments.linkNodeAttachment(incidentId, nodeId, attachmentId);
    }

    unlinkNodeAttachment(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void> {
        return this.attachments.unlinkNodeAttachment(incidentId, nodeId, attachmentId);
    }

    deleteAttachment(incidentId: RecordId, attachmentId: RecordId): Promise<void> {
        return this.attachments.deleteAttachment(incidentId, attachmentId);
    }

    importBundle(bundle: Blob, into?: RecordId): Promise<ImportReport> {
        return this.attachments.importBundle(bundle, into);
    }

    attachmentUrl(incidentId: RecordId, attachmentId: RecordId, usage: AttachmentUsage): string {
        return this.attachments.attachmentUrl(incidentId, attachmentId, usage);
    }

    bundleUrl(incidentId: RecordId): string {
        return this.attachments.bundleUrl(incidentId);
    }

}

/** Wraps an api in the viewer's own words, keeping its evidence files when it has any. */
export function relabelApi(api: TimelineApi, settings: () => AppSettings): RelabeledTimelineApi {
    return supportsAttachments(api) ? new RelabeledAttachmentApi(api, settings) : new RelabeledTimelineApi(api, settings);
}
