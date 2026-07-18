import { defineManifest } from "@absolutejs/manifest";
import { Type } from "@sinclair/typebox";

export const manifest = defineManifest<Record<string, never>>()({
  contract: 2,
  discovery: {
    audiences: ["platform-operators", "security-teams"],
    intents: [
      "ingest CISA known exploited vulnerabilities",
      "prioritize vulnerabilities with observed exploitation",
      "track CISA remediation due dates",
    ],
    keywords: ["CISA", "KEV", "CVE", "exploitation", "remediation"],
    protocols: ["CISA KEV JSON"],
  },
  identity: {
    accent: "#005ea8",
    category: "operations",
    description:
      "Official CISA Known Exploited Vulnerabilities ingestion with cache validators and complete remediation metadata.",
    docsUrl: "https://github.com/absolutejs/vulnerabilities-kev",
    name: "@absolutejs/vulnerabilities-kev",
    tagline: "Prioritize vulnerabilities attackers are actually exploiting.",
  },
  settings: Type.Object({}),
  wiring: [],
});
