import type { UpstreamDnsSource } from './upstreamDnsSource';

/**
 * /upstream_dns_sources/status response data
 */
export interface UpstreamDnsSourcesStatus {
    sources?: UpstreamDnsSource[];
}
