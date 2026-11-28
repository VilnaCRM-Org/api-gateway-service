# 0030. Streams through the gateway: WebSocket, SSE and GraphQL subscriptions

Status: accepted.

Planning decisions: sections 8.5 and 8.6 of `specs/8-iam-scaffolding-and-spikes/architecture.md` and requirements FR-61 and FR-62 of its `prd.md`. Stories 11.1 to 11.4 implement it; this record is added with Story 11.3.

## Context

A stream outlives the request that opened it. A WebSocket or an event stream that was authorized when it opened keeps flowing after its token expires, its role is revoked or its pod loses the proof of freshness, unless the gateway ends it. A GraphQL subscription adds a second problem: one socket carries many operations after one authentication, so the decision of the opening request says nothing about the fields that a later `subscribe` message selects.

## Decision

1. **A registry of streams.** Every WebSocket and SSE stream of a route flagged `streaming` is held in the stream registry under its subject and session, with its token expiry, the earliest expiry of the assignments that authorized it and the version of the snapshot that authorized it. The registry closes a stream at its token expiry, after `STREAM_IDLE_TIMEOUT` without traffic, at the earliest assignment expiry when the current snapshot no longer allows it, and when the pod may not serve (fenced, or its proof older than the hard bound). `GOAWAY` never reaches an upgraded connection, so the registry does it itself.
2. **Re-authorization by subject index.** When a version is applied, only the streams of the subjects, sessions, roles, routes and services it touched are decided again, with the decision rule of the pipeline. The pod reports the version as applied only after this finished.
3. **The gateway speaks the subscription protocol itself.** On a route flagged `graphql` and `streaming` the gateway answers the upgrade, for the subprotocols `graphql-transport-ws` and `graphql-ws` only, and decodes the frames in both directions with `tokio-tungstenite`. A client message is inspected, a message of the upstream passes through unchanged.
4. **Authentication before any upstream socket.** The gateway reads `connection_init` within `GRAPHQL_WS_INIT_TIMEOUT` (4408 on silence), takes the token from the upgrade request or else from the `authorization` member of the payload, verifies it (4401), authorizes the route on the authenticated principal (4403) and only then opens the upstream socket. The `connection_init` it forwards has `authorization` removed unless the upstream has `forwardCredentials = true`, so a token never travels in a message to an upstream that does not take credentials.
5. **A decision per operation.** Each `subscribe` or `start` message, and each query or mutation sent over the socket, is analysed with the analyzer and the limits of Story 10.8, the `Subscription` root fields included, and decided all or nothing before it is forwarded. A denial answers the id of the operation with an `error` carrying `extensions.code = FORBIDDEN`; the frame is not forwarded and the socket stays open. A payload that breaks the envelope rules of Story 10.8 (a persisted query, a member GraphQL does not define, no non-empty `query`) is answered the same way.
6. **Operations are registry entries.** An open operation is held in the registry with the subject, the session, the permission keys it rests on, the earliest expiry of its authorizing assignments and its document, so the same re-authorization decides it again. A denied operation gets `complete` towards the upstream and `error` towards the client; a revoked session or cut-off closes the socket with 4403. An operation does not count against the stream cap of its subject, which the socket that carries it already does.
7. **Bounds.** A client message is at most 64 KiB and a frame that does not decode closes the socket with 4400; a message of the upstream may be up to 1 MiB, since results are larger than requests.

## Consequences

- The gateway holds a socket for every client and a second one to the upstream, so a pod pays two connections per subscribing client and the registry holds one entry per open operation.
- The gateway reads every client frame of a GraphQL socket, which costs CPU but is what makes a per-operation decision possible; a plain `streaming` route is still spliced without parsing.
- A socket opened with the token of the upgrade request never needs the payload; a socket opened without one waits for `connection_init` and is bounded by `GRAPHQL_WS_INIT_TIMEOUT` and the edge connection limits.
- GraphQL over SSE and the per-socket operation cap follow in Story 11.4.

## Alternatives considered

| Option | Outcome | Reason |
| --- | --- | --- |
| Splice the socket without reading frames | rejected | one authentication would then cover every field a later `subscribe` selects |
| Authorize only at `connection_init` | rejected | a socket opened for one field could subscribe to fields the subject may not read |
| Open the upstream socket first and authenticate on the upstream | rejected | an unauthenticated client would hold an upstream connection and the upstream would see the token in a message |
| Close the whole socket on a denied operation | rejected | a client that mixes allowed and denied operations would lose the allowed ones |
