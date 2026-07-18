# @absolutejs/vulnerabilities-kev

Official CISA Known Exploited Vulnerabilities catalog ingestion for
`@absolutejs/vulnerabilities`.

```ts
import { createKevAdapter } from "@absolutejs/vulnerabilities-kev";

const adapter = createKevAdapter();
```

The adapter preserves each CVE's exploitation status, ransomware-campaign
field, required action, CISA due date, CWE identifiers, vendor, and product. It
validates catalog counts and duplicate identifiers before accepting a snapshot.
ETag and Last-Modified validators make unchanged refreshes return
`not_modified` without replacing cached intelligence.
