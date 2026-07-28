# Design Doc Template — Notion

```mermaid
C4Context
    title System Context
    Person(user, "User", "End user interacting with the system")
    Person(admin, "Admin", "System administrator")
    System_Boundary(system, "System Boundary") {
        System(api, "API Gateway", "Entry point for all client requests")
        System(app, "Application Service", "Core business logic")
        System(db, "Database", "Persistent storage")
    }
    System_Ext(external, "External Service", "Third-party dependency")
    Rel(user, api, "HTTP requests")
    Rel(api, app, "RPC calls")
    Rel(app, db, "Read/Write")
    Rel(app, external, "Integrates with")
    Rel(admin, app, "Configuration & monitoring")
```

---

# Design Doc: [System/Feature Name]

**Status:** [Draft | In Review | Approved]
**Related ADRs:** [Link to Redmine]

---

## 1. Context & Scope

[Technical requirement and business value — one paragraph.]

## 2. Goals & Non-Goals

### Goals

- [Target 1]
- [Target 2]

### Non-Goals

- [Explicit out-of-scope item 1]
- [Explicit out-of-scope item 2]

## 3. System Architecture

```mermaid
flowchart TB
    subgraph Client
        C[Browser / Mobile]
    end
    subgraph Edge
        LB[Load Balancer]
        CDN[CDN]
    end
    subgraph Services
        GW[API Gateway]
        SVC1[Service A]
        SVC2[Service B]
        Q[Message Queue]
    end
    subgraph Data
        DB[(Primary DB)]
        CACHE[(Cache)]
        QUEUE[(Queue Store)]
    end
    C --> CDN
    CDN --> LB
    LB --> GW
    GW --> SVC1
    GW --> SVC2
    SVC1 --> DB
    SVC2 --> DB
    SVC1 --> CACHE
    SVC2 --> Q
    Q --> QUEUE
```

[Explain component interactions; embed a diagram here or reference the one above.]

### 4.1 Domain Model

```mermaid
classDiagram
    class EntityA {
        +uuid id
        +string name
        +timestamp created_at
        +activate()
        +deactivate()
    }
    class EntityB {
        +uuid id
        +uuid entity_a_id
        +string status
        +jsonb payload
        +process()
        +archive()
    }
    class Service {
        +handle(request)
        +validate(payload)
        +emit(event)
    }
    EntityA "1" --> "*" EntityB : contains
    Service --> EntityA : manages
    Service --> EntityB : processes
```

```mermaid
stateDiagram-v2
    [*] --> Pending
    Pending --> Processing : validate
    Processing --> Completed : success
    Processing --> Failed : error
    Failed --> Pending : retry
    Completed --> Archived : ttl_expired
    Archived --> [*]
```

### 4.2 Data Models & Schemas

```mermaid
erDiagram
    ENTITY_A {
        uuid id PK
        string name
        timestamp created_at
    }
    ENTITY_B {
        uuid id PK
        uuid entity_a_id FK
        string status
        jsonb payload
    }
    ENTITY_A ||--o{ ENTITY_B : has
```

[Fenced code block for schemas]

```json
{
  "EntityA": {
    "id": "uuid",
    "name": "string",
    "created_at": "timestamp"
  },
  "EntityB": {
    "id": "uuid",
    "entity_a_id": "uuid",
    "status": "string",
    "payload": "object"
  }
}
```

### 4.2 Endpoints / RPCs

| Endpoint | Method | Purpose |
| :--- | :--- | :--- |
| [Endpoint Path] | [HTTP Method] | [Description] |

```mermaid
sequenceDiagram
    participant C as Client
    participant G as API Gateway
    participant S as Service
    participant D as Database
    C->>G: Request
    G->>S: Forward
    S->>D: Query
    D-->>S: Result
    S-->>G: Response
    G-->>C: Reply
```

## 5. Infrastructure & Compute

- **Compute:** [Compute node or job requirements]
- **Storage:** [Storage and IOPS requirements]
- **Algorithm Complexity:** [Big O for core processing logic]

```mermaid
flowchart LR
    subgraph Deploy
        A[Build] --> B[Test]
        B --> C[Staging]
        C --> D[Canary]
        D --> E[Production]
    end
    E --> F{Health Check}
    F -->|Pass| G[Done]
    F -->|Fail| H[Rollback]
    H --> C
```

## 6. Observability & Security

- **Metrics & Logs:** [Observability stack integration details]
- **Security:** [Access controls and encryption]

```mermaid
flowchart TB
    subgraph Observability
        APP[Application] -->|Metrics| PROM[Prometheus]
        APP -->|Logs| LOKI[Loki]
        APP -->|Traces| TEMPO[Tempo]
        PROM --> GRAF[Grafana]
        LOKI --> GRAF
        TEMPO --> GRAF
    end
    subgraph Alerting
        GRAF --> ALERT[Alertmanager]
        ALERT -->|Notify| PAGER[PagerDuty]
        ALERT -->|Notify| SLACK[Slack]
    end
```

## 7. Rollout Plan

1. [Phase 1 step]
2. [Phase 2 step]
3. **Rollback condition:** [Metric threshold triggering a revert]

```mermaid
gantt
    title Rollout Schedule
    dateFormat YYYY-MM-DD
    section Phase 1
    Deploy to Staging        :p1a, [YYYY-MM-DD], 2d
    Smoke Tests              :p1b, after p1a, 1d
    section Phase 2
    Canary 10%               :p2a, after p1b, 2d
    Monitor & Validate       :p2b, after p2a, 1d
    section Phase 3
    Gradual Rollout 50%      :p3a, after p2b, 2d
    Full Rollout 100%        :p3b, after p3a, 2d
    Rollback Window          :crit, after p3a, 3d
```
