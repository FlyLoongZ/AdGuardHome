import { createStore } from 'solid-js/store';
import { untrack } from 'solid-js';

import {
    upstreamDnsSourcesAddURL,
    upstreamDnsSourcesRefresh,
    upstreamDnsSourcesRemoveURL,
    upstreamDnsSourcesSetURL,
    upstreamDnsSourcesStatus,
} from 'panel/api/generated';
import intl from 'panel/common/intl';

import { addErrorToast, addSuccessToast } from './toasts';

export type UpstreamDnsSource = {
    id: number;
    name: string;
    url: string;
    enabled: boolean;
    rulesCount: number;
    lastUpdated: string;
    lastError?: string;
};

type UpstreamDnsSourcesState = {
    sources: UpstreamDnsSource[];
    processing: boolean;
    processingAdd: boolean;
    processingRemove: boolean;
    processingSet: boolean;
    processingRefresh: boolean;
};

const initialState: UpstreamDnsSourcesState = {
    sources: [],
    processing: true,
    processingAdd: false,
    processingRemove: false,
    processingSet: false,
    processingRefresh: false,
};

const [state, setState] = createStore<UpstreamDnsSourcesState>(initialState);

const normalizeUpstreamDnsSources = (sources: any[] = []): UpstreamDnsSource[] =>
    sources.map((source) => {
        const {
            id,
            url,
            enabled,
            last_updated: lastUpdated,
            last_error: lastError = '',
            name = 'Default name',
            rules_count: rulesCount = 0,
        } = source;

        return {
            id,
            url,
            enabled,
            lastUpdated,
            lastError,
            name,
            rulesCount,
        };
    });

export const getUpstreamDnsSources = async () => {
    setState('processing', true);
    try {
        const data = await upstreamDnsSourcesStatus();
        setState({
            sources: normalizeUpstreamDnsSources(data?.sources || []),
            processing: false,
        });
    } catch (error) {
        addErrorToast({ error });
        setState('processing', false);
    }
};

export const addUpstreamDnsSource = async (payload: {
    name: string;
    url: string;
}): Promise<boolean> => {
    setState('processingAdd', true);
    try {
        await upstreamDnsSourcesAddURL(payload);
        setState('processingAdd', false);
        addSuccessToast(intl.getMessage('upstream_dns_source_added_successfully'));
        await getUpstreamDnsSources();
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingAdd', false);
        return false;
    }
};

export const removeUpstreamDnsSource = async (url: string): Promise<boolean> => {
    setState('processingRemove', true);
    try {
        await upstreamDnsSourcesRemoveURL({ url });
        setState('processingRemove', false);
        addSuccessToast(intl.getMessage('upstream_dns_source_removed_successfully'));
        await getUpstreamDnsSources();
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingRemove', false);
        return false;
    }
};

export const setUpstreamDnsSource = async (
    currentUrl: string,
    payload: {
        name: string;
        url: string;
        enabled: boolean;
    },
): Promise<boolean> => {
    setState('processingSet', true);
    try {
        await upstreamDnsSourcesSetURL({
            url: currentUrl,
            data: payload,
        });
        setState('processingSet', false);
        addSuccessToast(intl.getMessage('upstream_dns_source_updated'));
        await getUpstreamDnsSources();
        return true;
    } catch (error) {
        addErrorToast({ error });
        setState('processingSet', false);
        return false;
    }
};

export const toggleUpstreamDnsSource = async (source: UpstreamDnsSource) => {
    return setUpstreamDnsSource(source.url, {
        name: source.name,
        url: source.url,
        enabled: !source.enabled,
    });
};

export const refreshUpstreamDnsSources = async () => {
    setState('processingRefresh', true);
    try {
        const data = await upstreamDnsSourcesRefresh();
        setState('processingRefresh', false);

        const updated = data?.updated || 0;
        if (updated > 0) {
            addSuccessToast(intl.getPlural('list_updated', updated));
        } else {
            addSuccessToast(intl.getMessage('all_lists_up_to_date_toast'));
        }

        await getUpstreamDnsSources();
    } catch (error) {
        addErrorToast({ error });
        setState('processingRefresh', false);
    }
};

export const upstreamDnsSourcesState = untrack(() => state);
