/**
 * /upstream_dns_sources/add_url request data
 */
export interface UpstreamDnsSourceAddRequest {
    name?: string;
    /** Source URL or absolute file path */
    url: string;
}
