// Files kept as evidence for an incident and tied to the steps they prove. Only a server that keeps them
// says so, by carrying the list in the diagram, and the workspace offers them only then.

import type { ImportReport } from "./document.js";
import type { RecordId, WallClock } from "./models.js";

export enum AttachmentKind {
    /** A picture the page may show: PNG, JPEG, GIF or WebP, told by its content rather than its name. */
    Image = "Image",
    /** Anything else, handled as if it were hostile: it only ever leaves the server inside a locked ZIP. */
    Sample = "Sample"
}

export enum AttachmentUsage {
    /** The picture itself, for an image shown in the page. Samples have none. */
    Preview = "preview",
    /** The file to keep: the image as it is, or a sample inside a ZIP locked with SAMPLE_ZIP_PASSWORD. */
    Download = "download"
}

/** The password analysts expect on a ZIP holding malware, so no tool on the way opens what is inside. */
export const SAMPLE_ZIP_PASSWORD = "infected";

export interface Attachment {
    id: RecordId;
    incidentId: RecordId;
    fileName: string;
    size: number;
    kind: AttachmentKind;
    /** The type the content was recognised as, for images; null for samples. */
    mediaType: string | null;
    md5: string;
    sha1: string;
    sha256: string;
    uploadedAt: WallClock;
    /** The steps the file is evidence for. A file may prove several, or wait for one in the incident. */
    stepIds: RecordId[];
    /** The records of kind File whose content it is. */
    nodeIds: RecordId[];
}

export interface AttachmentApi {
    listAttachments(incidentId: RecordId): Promise<Attachment[]>;
    uploadAttachment(incidentId: RecordId, file: Blob, fileName: string): Promise<Attachment>;
    linkAttachment(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void>;
    unlinkAttachment(incidentId: RecordId, stepId: RecordId, attachmentId: RecordId): Promise<void>;
    /** Makes the file the content of a record, typically one of kind File. */
    linkNodeAttachment(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void>;
    unlinkNodeAttachment(incidentId: RecordId, nodeId: RecordId, attachmentId: RecordId): Promise<void>;
    /**
     * Reads a bundle made by bundleUrl: the timeline and its files, into the incident given, or into a new
     * one. Files are tied back to the records they belonged to.
     */
    importBundle(bundle: Blob, into?: RecordId): Promise<ImportReport>;
    /** Where the browser downloads the incident as a bundle: the timeline with its files, in one ZIP. */
    bundleUrl(incidentId: RecordId): string;
    /** Removes the file from the incident and from every step it was tied to. */
    deleteAttachment(incidentId: RecordId, attachmentId: RecordId): Promise<void>;
    /** Where the browser fetches the file for the given use. */
    attachmentUrl(incidentId: RecordId, attachmentId: RecordId, usage: AttachmentUsage): string;
}

export function supportsAttachments<TApi extends object>(api: TApi): api is TApi & AttachmentApi {
    return "uploadAttachment" in api && typeof api.uploadAttachment === "function";
}
