# Last resolution trace

```mermaid
sequenceDiagram
    participant C as client
    participant Z0 as .
    participant Z1 as org.
    participant Z2 as example.org.
    Note over C: resolve example.org. A
    C->>Z0: example.org. A
    Z0-->>C: referral org. (match 0->1)
    C->>Z1: example.org. A
    Z1-->>C: referral example.org. (match 1->2)
    Note over C: glueless: resolve katelyn.ns.cloudflare.com.
    C->>Z2: example.org. A
    Z2-->>C: AA, 2 records
    Note over C: done

sequenceDiagram
    participant C as client
    participant Z0 as .
    participant Z1 as com.
    participant Z2 as cloudflare.com.
    Note over C: resolve katelyn.ns.cloudflare.com. A
    C->>Z0: katelyn.ns.cloudflare.com. A
    Z0-->>C: referral com. (match 0->1)
    C->>Z1: katelyn.ns.cloudflare.com. A
    Z1-->>C: referral cloudflare.com. (match 1->2)
    C->>Z2: katelyn.ns.cloudflare.com. A
    Z2-->>C: AA, 3 records
    Note over C: done
```
