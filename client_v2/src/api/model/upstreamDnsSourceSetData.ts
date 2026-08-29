/**
 * Upstream DNS source update data
 */
export interface UpstreamDnsSourceSetData {
    name?: string;
    url?: string;
    /** When omitted, the current enabled state is preserved. */
    enabled?: boolean;
}
