# Sample Architecture

```mermaid
flowchart LR
  Client["Web Client"] -->|HTTPS| Gateway["Payments Gateway"]
  subgraph AppBoundary["Application Boundary"]
    Gateway --> Processor["Payment Processor"]
    Processor --> Store["Payment Store"]
  end
```
