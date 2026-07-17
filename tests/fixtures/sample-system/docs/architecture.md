# Sample Architecture

```mermaid
flowchart LR
  Client["Web Client"] -->|HTTPS| Gateway["Payments Gateway"]
  Gateway --> Processor["Payment Processor"]
  Processor --> Store["Payment Store"]
```
