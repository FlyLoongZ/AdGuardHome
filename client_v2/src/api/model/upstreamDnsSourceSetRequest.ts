import type { UpstreamDnsSourceSetData } from './upstreamDnsSourceSetData';

/**
 * /upstream_dns_sources/set_url request data
 */
export interface UpstreamDnsSourceSetRequest {
    /** Existing source URL */
    url: string;
    data: UpstreamDnsSourceSetData;
}
