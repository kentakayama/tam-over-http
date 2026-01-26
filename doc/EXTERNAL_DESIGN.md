## TAM's External Design

```mermaid
---
title: Web API
---

flowchart TB

TCDeveloper([TC Developer]) -- POST SUIT Manifest --> HTTPServer
DeviceManager([Device Manager]) -- GET AgentStatus<br/>GET Manifests --> HTTPServer
TEEPAgent([TEEP Agent]) -- POST TEEP Message --> HTTPServer

subgraph TAM Server
    HTTPServer[HTTP Server]
    TAMoverHTTP[TAM]
    DBMS[DB]

    HTTPServer --> TAMoverHTTP
    TAMoverHTTP --> DBMS
    HTTPServer --> DBMS
end

```

Method | Endpoint | Requester | Input | Output | Reference
--|--|--|--|--|--
POST | `/tam` | TEEP Agent | empty<br/>QueryResponse<br/>Success<br/>Error | 200: QueryRequest<br/>200: Update / QueryRequest<br/>204: empty<br/>204: empty | [TEEP_MESSAGE_HANDLE](TEEP_MESSAGE_HANDLE.md)
GET | `/tc-developer/getManifests` | TC Developer | `{TBD}` | 200: `[overview of SUIT Manifest]`
POST | `/tc-developer/addManifest` | TC Developer | SUIT Manifest | 200: OK
GET | `/dev-admin/getAgents` | Device Manager Admin | `{TBD}` | 200: `{TBD}` (status of Agents owned by the Device Manager Admin)
