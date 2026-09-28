# REST contract

`HttpTimelineApi` talks to any server implementing this contract. `createTimelineHandler` implements it on
Node; a backend in another language only has to answer the same routes with the same shapes. The types
named below are exported from `cyber-incidents-timeline-generator/core` and are the reference for every field.

All bodies are JSON. Requests with a body must send `Content-Type: application/json`. Paths are relative to
the base path, `/api` by default.

## Conventions

- **Times** are wall clock readings without a zone, such as `2026-01-12T08:30:00`. A zone suffix sent by a
  client is dropped, not applied. Dates alone are accepted and read as midnight.
- **Vocabulary** fields (`side`, `kind`, `attackTactic`, `responsePhase`, `outcome`, `confidence`, `involvement`
  and the entries of `audiences`) are keys of the lists in the catalog the server is configured with, for
  example `"Attacker"` or `"InitialAccess"`. A deployment may add or remove entries, so read `GET /catalog`
  rather than assume the built in keys. Anything else is refused.
- **Meanings.** Each side carries a `role`, each response phase the `stage` of the response figures it counts
  toward, each outcome a `meaning` and each tactic its `killChainPhase`. The views and the metrics read those,
  so an entry added to a list is drawn and measured like the built in entry it resembles.
- **Audiences.** A step lists the audiences it is written for in `audiences`. An empty list means everyone.
  A client written before 0.5.0 may still send a single `audience`, which is read as a list of one, or as
  everyone when it is `"Both"`.
- **Ratings** (`impact`, `criticality`, `severity`) are level keys of the impact scale the server is configured
  with, listed in `catalog.impactScale`. Anything else is refused.
- **Incidents owned by another tool** carry its key in `externalId`, `null` otherwise. See
  [CONNECTORS.md](../CONNECTORS.md).
- **Creates** need only the required fields and fill the rest with defaults.
- **Updates** change only the fields present. A field sent as `null` is cleared.
- **Scoping.** Every record route names its incident. A record of another incident answers `404`, and a
  reference to one answers `400`.

## Routes

| Method | Path | Body | Success | Permission |
|---|---|---|---|---|
| GET | `/catalog` | | `200 Catalog` | Read |
| GET | `/catalog/settings` | | `200 CatalogSettings` | Read |
| PUT | `/catalog/settings` | `CatalogSettings` | `200 Catalog` | Configure |
| POST | `/catalog/usage` | `CatalogSettings` | `200 CatalogUsageEntry[]` | Configure |
| GET | `/incidents` | | `200 Incident[]` | Read |
| POST | `/incidents` | `IncidentCreateInput` | `201 Incident` | Create |
| GET | `/incidents/{incidentId}` | | `200 Incident` | Read |
| PUT | `/incidents/{incidentId}` | `IncidentUpdateInput` | `204` | Update |
| DELETE | `/incidents/{incidentId}` | | `204` | Delete |
| GET | `/incidents/{incidentId}/diagram` | | `200 Diagram` | Read |
| POST | `/incidents/{incidentId}/nodes` | `NodeCreateInput` | `201 DiagramNode` | Create |
| PUT | `/incidents/{incidentId}/nodes/{id}` | `NodeUpdateInput` | `204` | Update |
| DELETE | `/incidents/{incidentId}/nodes/{id}` | | `204` | Delete |
| POST | `/incidents/{incidentId}/steps` | `StepCreateInput` | `201 DiagramStep` | Create |
| PUT | `/incidents/{incidentId}/steps/{id}` | `StepUpdateInput` | `204` | Update |
| DELETE | `/incidents/{incidentId}/steps/{id}` | | `204` | Delete |
| POST | `/incidents/{incidentId}/links` | `LinkCreateInput` | `201 DiagramLink` | Create |
| PUT | `/incidents/{incidentId}/links/{id}` | `LinkUpdateInput` | `204` | Update |
| DELETE | `/incidents/{incidentId}/links/{id}` | | `204` | Delete |
| PUT | `/incidents/{incidentId}/layout` | `LayoutInput[]` | `204` | Update |
| GET | `/incidents/{incidentId}/summary` | | `200 DiagramSummary` | Read |
| GET | `/incidents/{incidentId}/document` | | `200 TimelineDocument` | Read |
| POST | `/documents` | `ImportBody` | `201 ImportReport` | Create |
| POST | `/incidents/{incidentId}/document` | `ImportBody` | `200 ImportReport` | Create |

### Required fields

| Input | Required |
|---|---|
| `IncidentCreateInput` | `title` |
| `NodeCreateInput` | `name`, `kind` |
| `StepCreateInput` | `title`, `timestamp` |
| `LinkCreateInput` | `sourceNodeId`, `targetNodeId` |
| `LayoutInput` | `nodeId`, `representation`, `x`, `y` (both `null` to release a pinned record) |

### Moving a whole timeline

`GET /incidents/{incidentId}/document` returns every record, step, relationship and pinned position as one
file. It carries no database id, no incident id and nothing about the deployment: records are named after
what identifies them, which is what lets an import recognise the same host arriving a second time.

`POST /documents` writes it into a new incident; `POST /incidents/{incidentId}/document` writes it into one
that already exists. The body is `{ document, mode?, title?, shiftHours? }`:

- `mode` is `merge`, which updates a record the document names again, or `add`, which always writes a new
  one. Merge is the default.
- `title` overrides the title the document carries.
- `shiftHours` moves every moment together, for replaying an exercise on another date.

The whole import runs in one transaction, so a file that turns out to be inconsistent leaves nothing half
written. A milestone key a step in the incident already holds is reported in `milestonesTaken` and left
where it was, rather than displacing it.

### Side effects

- Deleting a record deletes the records grouped under it and the relationships touching any of them. Steps
  that named them as author, target or involved record are kept without that mention.
- Deleting a step deletes the relationships it established.
- Deleting an incident deletes everything in it.

### Changing the catalog

A deployment may let its users fit the vocabulary, the impact scale and the milestones to their own needs.
`CatalogSettings` holds `impactScale`, `milestones` and `vocabulary`, each list of which replaces the list of
the same name whole; `null` or a list left out keeps what the server was built with.

- `PUT /catalog/settings` checks that the settings hold together, keeps them and answers the catalog that
  results. Settings that do not fit, such as a tactic landing in a kill chain phase the lists no longer have,
  answer `400`. A server keeping its catalog in code, with no catalog store, answers `409`.
- `POST /catalog/usage` answers, for settings not yet saved, each entry they remove that records still hold,
  with the number of those records. Records are never rewritten: they keep the key and are drawn as unknown
  until edited, so a client asks first and confirms.
- A list must keep the entry records fall back to (`Unknown` for sides, outcomes and confidences, `None` for
  tactics and phases). `Both` is not an audience: an empty `audiences` means everyone.

## Example

```http
POST /api/incidents/7/steps
Content-Type: application/json

{
  "title": "Credentials replayed on the file server",
  "timestamp": "2026-01-12T13:00",
  "side": "Attacker",
  "attackTactic": "LateralMovement",
  "mitreTechniqueId": "T1021.002",
  "sourceNodeId": 31,
  "targetNodeId": 36,
  "audiences": ["Technical"],
  "isMilestone": true
}
```

```http
HTTP/1.1 201 Created
Content-Type: application/json; charset=utf-8

{ "id": 52, "timestamp": "2026-01-12T13:00:00", "killChainPhase": "ActionsOnObjectives", "...": "..." }
```

## Evidence files

Served by the reference server when it keeps files (`createAttachmentHandler`), and by nothing else. The
diagram then carries an `attachments` array; its absence means the server keeps none.

| Method | Path | Permission | Body and answer |
|---|---|---|---|
| `GET` | `/incidents/:id/attachments` | Read | The files of the incident, each with `stepIds` and `nodeIds` |
| `POST` | `/incidents/:id/attachments` | Create | The raw file as `application/octet-stream`, its name URL encoded in `X-File-Name`. Answers the file; the same content sent again answers the file already kept |
| `DELETE` | `/incidents/:id/attachments/:file` | Delete | Removes the file from the incident and every record |
| `GET` | `/incidents/:id/attachments/:file/content` | Read | An image as it is; anything else as a ZIP locked with the password `infected` |
| `GET` | `/incidents/:id/attachments/:file/content?usage=preview` | Read | An image inline, in a sandbox; 400 for anything else |
| `PUT` | `/incidents/:id/steps/:step/attachments/:file` | Update | Ties the file to the step |
| `DELETE` | `/incidents/:id/steps/:step/attachments/:file` | Update | Unties it |
| `PUT` | `/incidents/:id/nodes/:node/attachments/:file` | Update | Makes the file the content of the record |
| `DELETE` | `/incidents/:id/nodes/:node/attachments/:file` | Update | Takes it away |
| `GET` | `/incidents/:id/bundle` | Read | The incident with its files as one ZIP: `timeline.json`, `files.json`, pictures under `files/images/`, every other file in its own locked ZIP under `files/samples/` |
| `POST` | `/incidents/:id/bundle` | Create | A bundle as `application/octet-stream`, imported into the incident; answers the import report |
| `POST` | `/bundles` | Create | A bundle imported as a new incident |

A file is an image when its content starts like a PNG, JPEG, GIF or WebP, whatever its name; everything else,
SVG included, is handled as a sample. File answers carry `Content-Security-Policy: sandbox` and `nosniff`.

## Errors

Errors carry `{ "message": string }`, and validation errors add the issues found:

```json
{
  "message": "title is required; side must be one of Unknown, Attacker, Victim, Defender, ThirdParty",
  "issues": [
    { "field": "title", "message": "is required" },
    { "field": "side", "message": "must be one of Unknown, Attacker, Victim, Defender, ThirdParty" }
  ]
}
```

| Status | When |
|---|---|
| 400 | The body is not valid JSON, fails validation, or references a record of another incident |
| 403 | The `authorize` callback refused the request |
| 404 | No such route, incident or record in that incident |
| 405 | The route exists but not for that method; `Allow` lists the methods it takes |
| 409 | The catalog settings cannot be saved, because the server keeps its catalog in code |
| 413 | The body is larger than `maxBodyBytes` |
| 415 | A body was sent without `Content-Type: application/json` |
| 500 | Anything else; details are passed to `onError` and never returned |

## Authorization

`createTimelineHandler` calls `authorize(request, permission, incidentId)` before every route. `permission`
is `Read`, `Create`, `Update`, `Delete` or `Configure`, and `incidentId` is `null` for `/catalog` and `/incidents`.
`Configure` guards changing the catalog every incident is recorded against, so a host can let analysts edit
incidents and keep the vocabulary to administrators. Return
`false` to answer `403`. Omitting the callback allows everything, which is only suitable for a local tool.
