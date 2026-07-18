import type { FeedAdapter, FeedRecord } from "@absolutejs/vulnerabilities";

export const CISA_KEV_URL =
  "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";

export type KevEntry = {
  cveId: string;
  cwes: string[];
  dateAdded: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;
  notes: string;
  product: string;
  requiredAction: string;
  shortDescription: string;
  vendorProject: string;
  vulnerabilityName: string;
};

export type KevCatalog = {
  catalogVersion: string;
  count: number;
  dateReleased: string;
  title: string;
  vulnerabilities: KevEntry[];
};

export type KevFetch = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

type JsonObject = Record<string, unknown>;

const object = (value: unknown, label: string): JsonObject => {
  if (typeof value !== "object" || value === null || Array.isArray(value))
    throw new Error(`${label} must be an object`);
  return value as JsonObject;
};

const text = (value: unknown, label: string) => {
  if (typeof value !== "string" || value.trim().length === 0)
    throw new Error(`${label} must be a non-empty string`);
  return value.trim();
};

const date = (value: unknown, label: string) => {
  const normalized = text(value, label);
  if (!/^\d{4}-\d{2}-\d{2}$/.test(normalized))
    throw new Error(`${label} must use YYYY-MM-DD`);
  return normalized;
};

const timestamp = (value: unknown, label: string) => {
  const normalized = text(value, label);
  if (!Number.isFinite(Date.parse(normalized)))
    throw new Error(`${label} must be a valid timestamp`);
  return normalized;
};

export const normalizeKevCatalog = (input: unknown): KevCatalog => {
  const catalog = object(input, "CISA KEV catalog");
  if (!Array.isArray(catalog.vulnerabilities))
    throw new Error("CISA KEV vulnerabilities must be an array");
  if (!Number.isInteger(catalog.count) || Number(catalog.count) < 0)
    throw new Error("CISA KEV count must be a non-negative integer");
  const vulnerabilities = catalog.vulnerabilities.map((entry) => {
    const item = object(entry, "CISA KEV entry");
    if (
      !Array.isArray(item.cwes) ||
      !item.cwes.every((cwe) => typeof cwe === "string")
    )
      throw new Error("CISA KEV cwes must be a string array");
    const cveId = text(item.cveID, "CISA KEV cveID").toUpperCase();
    if (!/^CVE-\d{4}-\d{4,}$/.test(cveId))
      throw new Error("CISA KEV cveID must be a CVE identifier");
    return {
      cveId,
      cwes: [...new Set(item.cwes.map((cwe) => cwe.trim()).filter(Boolean))],
      dateAdded: date(item.dateAdded, "CISA KEV dateAdded"),
      dueDate: date(item.dueDate, "CISA KEV dueDate"),
      knownRansomwareCampaignUse: text(
        item.knownRansomwareCampaignUse,
        "CISA KEV knownRansomwareCampaignUse",
      ),
      notes: typeof item.notes === "string" ? item.notes.trim() : "",
      product: text(item.product, "CISA KEV product"),
      requiredAction: text(item.requiredAction, "CISA KEV requiredAction"),
      shortDescription: text(
        item.shortDescription,
        "CISA KEV shortDescription",
      ),
      vendorProject: text(item.vendorProject, "CISA KEV vendorProject"),
      vulnerabilityName: text(
        item.vulnerabilityName,
        "CISA KEV vulnerabilityName",
      ),
    };
  });
  const count = Number(catalog.count);
  if (vulnerabilities.length !== count)
    throw new Error(
      `CISA KEV count mismatch: expected ${count}, received ${vulnerabilities.length}`,
    );
  if (new Set(vulnerabilities.map(({ cveId }) => cveId)).size !== count)
    throw new Error("CISA KEV catalog contains duplicate CVE identifiers");
  return {
    catalogVersion: text(catalog.catalogVersion, "CISA KEV catalogVersion"),
    count,
    dateReleased: timestamp(catalog.dateReleased, "CISA KEV dateReleased"),
    title: text(catalog.title, "CISA KEV title"),
    vulnerabilities,
  };
};

export const createKevAdapter = (
  options: {
    fetch?: KevFetch;
    url?: string;
  } = {},
): FeedAdapter<KevEntry> => {
  const url = options.url ?? CISA_KEV_URL;
  const fetcher = options.fetch ?? globalThis.fetch;
  return {
    descriptor: { id: "cisa-kev", name: "CISA KEV", url },
    fetch: async ({ cursor, signal }) => {
      const headers = new Headers();
      if (cursor?.etag) headers.set("if-none-match", cursor.etag);
      if (cursor?.lastModified)
        headers.set("if-modified-since", cursor.lastModified);
      const response = await fetcher(url, { headers, signal });
      if (response.status === 304) return { status: "not_modified" };
      if (!response.ok)
        throw new Error(`CISA KEV fetch failed with HTTP ${response.status}`);
      const catalog = normalizeKevCatalog(await response.json());
      const records: FeedRecord<KevEntry>[] = catalog.vulnerabilities.map(
        (value) => ({
          id: value.cveId,
          modifiedAt: catalog.dateReleased,
          value,
        }),
      );
      return {
        cursor: {
          etag: response.headers.get("etag"),
          lastModified: response.headers.get("last-modified"),
          token: null,
        },
        fetchedAt: new Date().toISOString(),
        records,
        replaceAll: true,
        revision: catalog.catalogVersion,
        status: "updated",
      };
    },
  };
};
