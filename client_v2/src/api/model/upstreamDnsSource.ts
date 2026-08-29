/**
 * Upstream DNS source list used for domain-specific routing
 */
export interface UpstreamDnsSource {
    id?: number;
    /** Source URL or absolute file path */
    url?: string;
    name?: string;
    enabled?: boolean;
    rules_count?: number;
    last_updated?: string;
    /** Last non-fatal load or refresh error for this source, if any. Present when an enabled source failed to download or its cache is missing and rules were skipped. */
    last_error?: string;
}
