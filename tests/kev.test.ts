import { describe, expect, test } from "bun:test";
import { createKevAdapter, normalizeKevCatalog, type KevFetch } from "../src";

const entry = {
  cveID: "CVE-2026-58644",
  cwes: ["CWE-502"],
  dateAdded: "2026-07-16",
  dueDate: "2026-07-19",
  knownRansomwareCampaignUse: "Unknown",
  notes: "https://example.test/advisory",
  product: "SharePoint",
  requiredAction: "Apply vendor mitigations.",
  shortDescription: "Deserialization of untrusted data.",
  vendorProject: "Microsoft",
  vulnerabilityName: "SharePoint deserialization vulnerability",
};
const catalog = {
  catalogVersion: "2026.07.16",
  count: 1,
  dateReleased: "2026-07-16T17:00:15.6845Z",
  title: "CISA Catalog of Known Exploited Vulnerabilities",
  vulnerabilities: [entry],
};

describe("CISA KEV normalization", () => {
  test("preserves exploitation and remediation metadata", () => {
    const result = normalizeKevCatalog(catalog);
    expect(result.vulnerabilities[0]).toEqual({
      cveId: entry.cveID,
      cwes: entry.cwes,
      dateAdded: entry.dateAdded,
      dueDate: entry.dueDate,
      knownRansomwareCampaignUse: entry.knownRansomwareCampaignUse,
      notes: entry.notes,
      product: entry.product,
      requiredAction: entry.requiredAction,
      shortDescription: entry.shortDescription,
      vendorProject: entry.vendorProject,
      vulnerabilityName: entry.vulnerabilityName,
    });
  });

  test("rejects count mismatches and invalid CVEs", () => {
    expect(() => normalizeKevCatalog({ ...catalog, count: 2 })).toThrow(
      "count mismatch",
    );
    expect(() =>
      normalizeKevCatalog({
        ...catalog,
        vulnerabilities: [{ ...entry, cveID: "not-a-cve" }],
      }),
    ).toThrow("CVE identifier");
  });
});

describe("CISA KEV adapter", () => {
  test("uses validators and returns not-modified", async () => {
    let headers = new Headers();
    const fetcher: KevFetch = async (_input, init) => {
      headers = new Headers(init?.headers);
      return new Response(null, { status: 304 });
    };
    const result = await createKevAdapter({ fetch: fetcher }).fetch({
      cursor: {
        etag: '"catalog-1"',
        lastModified: "Thu, 16 Jul 2026 17:00:15 GMT",
        token: null,
      },
    });
    expect(headers.get("if-none-match")).toBe('"catalog-1"');
    expect(headers.get("if-modified-since")).toContain("16 Jul 2026");
    expect(result).toEqual({ status: "not_modified" });
  });

  test("returns a complete replacement snapshot with response validators", async () => {
    const fetcher: KevFetch = async () =>
      Response.json(catalog, {
        headers: {
          etag: '"catalog-2"',
          "last-modified": "Thu, 16 Jul 2026 17:00:15 GMT",
        },
      });
    const result = await createKevAdapter({ fetch: fetcher }).fetch({
      cursor: null,
    });
    expect(result.status).toBe("updated");
    if (result.status !== "updated") throw new Error("Expected update");
    expect(result.cursor.etag).toBe('"catalog-2"');
    expect(result.records[0]?.id).toBe(entry.cveID);
    expect(result.revision).toBe(catalog.catalogVersion);
    expect(result.replaceAll).toBe(true);
  });
});
