// Routes of the evidence files. Bodies are the raw file rather than JSON, so they get a handler of their own,
// chained before the REST contract and asking the same authorizer.

import type { IncomingMessage, ServerResponse } from "node:http";
import { AttachmentKind, AttachmentUsage, SAMPLE_ZIP_PASSWORD, type Attachment } from "../core/attachments.js";
import { Permission } from "../core/enums.js";
import { ForbiddenError, ValidationError } from "../core/errors.js";
import type { RecordId } from "../core/models.js";
import type { AttachmentAwareService, AttachmentStore } from "./attachments.js";
import { exportBundle, importBundle } from "./bundle.js";
import { cleanFileName } from "./attachments.js";
import {
    HttpStatus,
    PayloadTooLargeError,
    UnsupportedMediaTypeError,
    errorBody,
    parseId,
    send,
    statusOf,
    type Authorizer,
    type TimelineRequestHandler
} from "./http.js";
import { ZipFormatError, lockedZip } from "./zip.js";

export const DEFAULT_MAX_ATTACHMENT_BYTES = 50 * 1024 * 1024;
export const DEFAULT_MAX_BUNDLE_BYTES = 500 * 1024 * 1024;
const BUNDLE_SUFFIX = ".timeline.zip";
export const FILE_NAME_HEADER = "x-file-name";
const RAW_BODY = /^application\/octet-stream\b/i;
const ZIP_SUFFIX = ".zip";

// Nothing a file holds may run in the page: no script, no frame, no form, whatever the browser thinks it is
const FILE_SECURITY_POLICY = "default-src 'none'; img-src 'self'; style-src 'unsafe-inline'; sandbox";

export interface AttachmentHttpOptions {
    store: AttachmentStore;
    /** Enables bundles, which import timelines as well as files. */
    service?: AttachmentAwareService;
    maxBundleBytes?: number;
    basePath?: string;
    authorize?: Authorizer;
    maxBytes?: number;
    onError?: (error: unknown) => void;
}

interface AttachmentRoute {
    permission: Permission;
    handle(request: IncomingMessage, response: ServerResponse, url: URL): Promise<void>;
}

async function readFile(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
    if (!RAW_BODY.test(request.headers["content-type"] ?? "")) {
        throw new UnsupportedMediaTypeError("Send the file as application/octet-stream.");
    }
    const declared = Number(request.headers["content-length"]);
    if (Number.isFinite(declared) && declared > maxBytes) {
        throw new PayloadTooLargeError(`The file is larger than ${maxBytes} bytes.`);
    }
    const chunks: Buffer[] = [];
    let size = 0;
    for await (const chunk of request) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
        size += buffer.length;
        if (size > maxBytes) {
            throw new PayloadTooLargeError(`The file is larger than ${maxBytes} bytes.`);
        }
        chunks.push(buffer);
    }
    return Buffer.concat(chunks);
}

function headerFileName(request: IncomingMessage): string {
    const raw = request.headers[FILE_NAME_HEADER];
    const value = Array.isArray(raw) ? raw[0] : raw;
    try {
        return cleanFileName(value ? decodeURIComponent(value) : null);
    } catch {
        return cleanFileName(value);
    }
}

/** A header naming the file both for old browsers, in plain ASCII, and for the rest, in UTF-8. */
function disposition(type: "inline" | "attachment", fileName: string): string {
    const plain = fileName.replace(/[^A-Za-z0-9._-]/g, "_");
    return `${type}; filename="${plain}"; filename*=UTF-8''${encodeURIComponent(fileName)}`;
}

function sendFile(response: ServerResponse, contentType: string, contentDisposition: string, body: Buffer): void {
    response.statusCode = HttpStatus.Ok;
    response.setHeader("Content-Type", contentType);
    response.setHeader("Content-Disposition", contentDisposition);
    response.setHeader("Content-Length", body.length);
    response.setHeader("Cache-Control", "no-store");
    response.setHeader("X-Content-Type-Options", "nosniff");
    response.setHeader("Content-Security-Policy", FILE_SECURITY_POLICY);
    response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
    response.end(body);
}

function usageOf(url: URL): AttachmentUsage {
    return url.searchParams.get("usage") === AttachmentUsage.Preview ? AttachmentUsage.Preview : AttachmentUsage.Download;
}

/**
 * Serves the evidence files. Resolves to false for anything else, so the REST contract answers it.
 */
export function createAttachmentHandler(options: AttachmentHttpOptions): TimelineRequestHandler {
    const basePath = (options.basePath ?? "/api").replace(/\/+$/, "");
    const { store } = options;
    const authorize: Authorizer = options.authorize ?? (() => true);
    const maxBytes = options.maxBytes ?? DEFAULT_MAX_ATTACHMENT_BYTES;
    const onError = options.onError ?? (error => console.error(error));
    const { service } = options;
    const maxBundleBytes = options.maxBundleBytes ?? DEFAULT_MAX_BUNDLE_BYTES;

    const bundleImport = (into: RecordId | undefined): AttachmentRoute | null => service ? {
        permission: Permission.Create,
        handle: async (request, response) => {
            const bundle = await readFile(request, maxBundleBytes);
            try {
                send(response, HttpStatus.Created, await importBundle(service, store, bundle, into));
            } catch (error) {
                // A damaged or foreign archive is the sender's mistake, not the server's
                throw error instanceof ZipFormatError ? new ValidationError([{ field: "bundle", message: error.message }]) : error;
            }
        }
    } : null;

    const routeFor = (method: string | undefined, segments: readonly string[]): { incidentId: RecordId | null; route: AttachmentRoute } | null => {
        const [root, incidentSegment, collection, ...rest] = segments;
        // /bundles: a bundle becoming a new incident
        if (root === "bundles" && segments.length === 1 && method === "POST") {
            const route = bundleImport(undefined);
            return route ? { incidentId: null, route } : null;
        }
        const incidentId = parseId(incidentSegment ?? "");
        if (root !== "incidents" || incidentId === null) return null;

        // /incidents/:id/attachments[/:attachment[/content]]
        if (collection === "attachments") {
            const [attachmentSegment, content, ...extra] = rest;
            if (extra.length > 0) return null;
            if (attachmentSegment === undefined) {
                if (method === "GET") return { incidentId, route: { permission: Permission.Read, handle: async (_request, response) => send(response, HttpStatus.Ok, await store.list(incidentId)) } };
                if (method === "POST") return {
                    incidentId,
                    route: {
                        permission: Permission.Create,
                        handle: async (request, response) => send(response, HttpStatus.Created, await store.add(incidentId, headerFileName(request), await readFile(request, maxBytes)))
                    }
                };
                return null;
            }
            const attachmentId = parseId(attachmentSegment);
            if (attachmentId === null) return null;
            if (content === undefined && method === "DELETE") {
                return { incidentId, route: { permission: Permission.Delete, handle: async (_request, response) => { await store.remove(incidentId, attachmentId); send(response, HttpStatus.NoContent); } } };
            }
            if (content === "content" && method === "GET") {
                return { incidentId, route: { permission: Permission.Read, handle: async (_request, response, url) => serve(response, incidentId, attachmentId, usageOf(url)) } };
            }
            return null;
        }

        // /incidents/:id/bundle
        if (collection === "bundle" && rest.length === 0 && service) {
            if (method === "GET") return {
                incidentId,
                route: {
                    permission: Permission.Read,
                    handle: async (_request, response) => {
                        const title = (await service.getIncident(incidentId)).title;
                        sendFile(response, "application/zip", disposition("attachment", `${slug(title)}${BUNDLE_SUFFIX}`), await exportBundle(service, store, incidentId));
                    }
                }
            };
            const route = method === "POST" ? bundleImport(incidentId) : null;
            return route ? { incidentId, route } : null;
        }

        // /incidents/:id/nodes/:node/attachments/:attachment
        if (collection === "nodes") {
            const [nodeSegment, attachments, attachmentSegment, ...extra] = rest;
            const nodeId = parseId(nodeSegment ?? "");
            const attachmentId = parseId(attachmentSegment ?? "");
            if (attachments !== "attachments" || nodeId === null || attachmentId === null || extra.length > 0) return null;
            if (method === "PUT") return { incidentId, route: { permission: Permission.Update, handle: async (_request, response) => { await store.linkNode(incidentId, nodeId, attachmentId); send(response, HttpStatus.NoContent); } } };
            if (method === "DELETE") return { incidentId, route: { permission: Permission.Update, handle: async (_request, response) => { await store.unlinkNode(incidentId, nodeId, attachmentId); send(response, HttpStatus.NoContent); } } };
            return null;
        }

        // /incidents/:id/steps/:step/attachments/:attachment
        if (collection === "steps") {
            const [stepSegment, attachments, attachmentSegment, ...extra] = rest;
            const stepId = parseId(stepSegment ?? "");
            const attachmentId = parseId(attachmentSegment ?? "");
            if (attachments !== "attachments" || stepId === null || attachmentId === null || extra.length > 0) return null;
            if (method === "PUT") return { incidentId, route: { permission: Permission.Update, handle: async (_request, response) => { await store.link(incidentId, stepId, attachmentId); send(response, HttpStatus.NoContent); } } };
            if (method === "DELETE") return { incidentId, route: { permission: Permission.Update, handle: async (_request, response) => { await store.unlink(incidentId, stepId, attachmentId); send(response, HttpStatus.NoContent); } } };
        }
        return null;
    };

    const serve = async (response: ServerResponse, incidentId: RecordId, attachmentId: RecordId, usage: AttachmentUsage): Promise<void> => {
        const { attachment, content } = await store.read(incidentId, attachmentId);
        if (attachment.kind === AttachmentKind.Image && attachment.mediaType) {
            sendFile(response, attachment.mediaType, disposition(usage === AttachmentUsage.Preview ? "inline" : "attachment", attachment.fileName), content);
            return;
        }
        if (usage === AttachmentUsage.Preview) {
            throw new ValidationError([{ field: "usage", message: "has no preview for a file that is not an image" }]);
        }
        sendFile(response, "application/zip", disposition("attachment", zipName(attachment)), lockedZip(attachment.fileName, content, SAMPLE_ZIP_PASSWORD));
    };

    return async (request, response) => {
        const url = new URL(request.url ?? "/", "http://localhost");
        if (!url.pathname.startsWith(`${basePath}/`)) return false;
        const found = routeFor(request.method, url.pathname.slice(basePath.length).split("/").filter(Boolean));
        if (!found) return false;

        try {
            if (!(await authorize(request, found.route.permission, found.incidentId))) {
                throw new ForbiddenError("You may not do this.");
            }
            await found.route.handle(request, response, url);
        } catch (error) {
            const status = statusOf(error);
            if (status === HttpStatus.InternalServerError) onError(error);
            // A refused upload may still be streaming in; it is answered at once and the rest is dropped
            response.setHeader("Connection", "close");
            send(response, status, errorBody(error, status));
        }
        return true;
    };
}

function slug(title: string): string {
    return title.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^A-Za-z0-9]+/g, "-").replace(/^-|-$/g, "").toLowerCase().slice(0, 60) || "incident";
}

function zipName(attachment: Attachment): string {
    return `${attachment.fileName}${ZIP_SUFFIX}`;
}
