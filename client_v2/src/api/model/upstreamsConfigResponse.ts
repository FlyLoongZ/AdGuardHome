import type { UpstreamsConfigResponseFallback } from './upstreamsConfigResponseFallback';
import type { UpstreamsConfigResponseGeneral } from './upstreamsConfigResponseGeneral';
import type { UpstreamsConfigResponsePrivate } from './upstreamsConfigResponsePrivate';

/**
 * Upstreams configuration response
 */
export interface UpstreamsConfigResponse {
    general?: UpstreamsConfigResponseGeneral;
    fallback?: UpstreamsConfigResponseFallback;
    private?: UpstreamsConfigResponsePrivate;
}
