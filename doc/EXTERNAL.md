## TAM's External Design

```mermaid
---
title: Web API
---

flowchart TB

TCDeveloper([TC Developer]) -- POST SUIT Manifest --> HTTPServer
HTTPServer -- GET AgentStatus --> DeviceManager([Device Manager])
TEEPAgent([TEEP Agent]) <-- POST TEEP Message --> HTTPServer

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
POST | `/tam` | TEEP Agent | empty<br/>QueryResponse<br/>Success<br/>Error | 200: QueryRequest<br/>200: Update / QueryResponse<br/>204: empty<br/>204: empty | [TEEP_MESSAGE_HANDLE](TEEP_MESSAGE_HANDLE.md)
POST | `/api/addManigest` | TC Developer | SUIT Manifest | 200: OK
GET | `/api/getAgents` | Device Manager | `{TBD}` | 200: `{TBD}`
