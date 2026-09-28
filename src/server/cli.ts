#!/usr/bin/env node
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import { seedSampleData } from "../core/sample.js";
import { TimelineService } from "../core/service.js";
import { AttachmentAwareService, AttachmentStore, createAttachmentHandler, createTimelineServer, openSqliteStore, type TimelineRequestHandler } from "./index.js";

const COMMAND = "cyber-incidents-timeline-generator";
const DEFAULT_PORT = "8080";
const DEFAULT_HOST = "127.0.0.1";
const DEFAULT_DATABASE = "timeline.sqlite";
const HIGHEST_PORT = 65535;
const IN_MEMORY = ":memory:";
const DEFAULT_MAX_ATTACHMENT_MB = "50";
const BYTES_PER_MEGABYTE = 1024 * 1024;

// The incident app ships inside the package, two folders above this file once compiled
const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

const { values } = parseArgs({
    options: {
        db: { type: "string", default: DEFAULT_DATABASE },
        port: { type: "string", default: DEFAULT_PORT },
        host: { type: "string", default: DEFAULT_HOST },
        "api-only": { type: "boolean", default: false },
        seed: { type: "boolean", default: false },
        attachments: { type: "string" },
        "no-attachments": { type: "boolean", default: false },
        "max-attachment-mb": { type: "string", default: DEFAULT_MAX_ATTACHMENT_MB },
        help: { type: "boolean", default: false }
    }
});

if (values.help) {
    console.log(`Usage: ${COMMAND} [options]

  --db <file>    SQLite file to use (default ${DEFAULT_DATABASE}, ":memory:" for a throwaway one)
  --port <port>  Port to listen on (default ${DEFAULT_PORT})
  --host <host>  Interface to bind (default ${DEFAULT_HOST}, local only)
  --api-only     Serve the REST API alone, without the incident app
  --seed         Add the sample incident when the database holds none
  --attachments <dir>        Folder for evidence files (default "attachments" beside the database)
  --no-attachments           Keep no evidence files
  --max-attachment-mb <mb>   Largest evidence file accepted (default ${DEFAULT_MAX_ATTACHMENT_MB})
`);
    process.exit(0);
}

const port = Number(values.port);
if (!Number.isInteger(port) || port < 1 || port > HIGHEST_PORT) {
    console.error(`--port must be a number between 1 and ${HIGHEST_PORT}, not ${values.port}.`);
    process.exit(1);
}

const maxAttachmentMb = Number(values["max-attachment-mb"]);
if (!Number.isFinite(maxAttachmentMb) || maxAttachmentMb <= 0) {
    console.error(`--max-attachment-mb must be a positive number, not ${values["max-attachment-mb"]}.`);
    process.exit(1);
}

const { driver, store, catalogStore } = await openSqliteStore(values.db);
// A throwaway database keeps files only when a folder is named for them, since they would outlive it
const attachmentFolder = values["no-attachments"] ? null : values.attachments ?? (values.db === IN_MEMORY ? null : join(dirname(resolve(values.db)), "attachments"));
const attachmentStore = attachmentFolder ? await AttachmentStore.open(driver, store.tables, attachmentFolder) : null;
const attachments = attachmentStore ? new AttachmentAwareService(store, attachmentStore, { catalogStore }) : null;
const service = attachments ?? new TimelineService(store, { catalogStore });
const handlers: TimelineRequestHandler[] = attachmentStore && attachments
    ? [createAttachmentHandler({ store: attachmentStore, service: attachments, maxBytes: maxAttachmentMb * BYTES_PER_MEGABYTE })]
    : [];

if (values.seed && (await service.listIncidents()).length === 0) {
    const incident = await seedSampleData(service);
    console.log(`Seeded "${incident.title}" as incident ${incident.id}.`);
}

const server = createTimelineServer({
    api: service,
    handlers,
    staticMounts: values["api-only"] ? [] : [
        { prefix: "/dist/", directory: resolve(PACKAGE_ROOT, "dist") },
        { prefix: "/styles/", directory: resolve(PACKAGE_ROOT, "styles") },
        { prefix: "/", directory: resolve(PACKAGE_ROOT, "app") }
    ]
});

server.listen(port, values.host, () => {
    const origin = `http://${values.host}:${port}`;
    console.log(`Timeline generator listening on ${origin}`);
    console.log(`REST API under ${origin}/api`);
    console.log(attachmentFolder ? `Evidence files kept in ${attachmentFolder}, up to ${maxAttachmentMb} MB each` : "No evidence files are kept");
    if (!values["api-only"]) {
        console.log(`Incident app at ${origin}/, or ${origin}/local.html to keep incidents in the browser only`);
    }
});
