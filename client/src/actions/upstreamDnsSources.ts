import { createAction } from 'redux-actions';
import i18next from 'i18next';

import apiClient from '../api/Api';
import { addErrorToast, addSuccessToast } from './toasts';
import { normalizeFilters } from '../helpers/helpers';

export const getUpstreamDnsSourcesRequest = createAction('GET_UPSTREAM_DNS_SOURCES_REQUEST');
export const getUpstreamDnsSourcesFailure = createAction('GET_UPSTREAM_DNS_SOURCES_FAILURE');
export const getUpstreamDnsSourcesSuccess = createAction('GET_UPSTREAM_DNS_SOURCES_SUCCESS');

export const addUpstreamDnsSourceRequest = createAction('ADD_UPSTREAM_DNS_SOURCE_REQUEST');
export const addUpstreamDnsSourceFailure = createAction('ADD_UPSTREAM_DNS_SOURCE_FAILURE');
export const addUpstreamDnsSourceSuccess = createAction('ADD_UPSTREAM_DNS_SOURCE_SUCCESS');

export const removeUpstreamDnsSourceRequest = createAction('REMOVE_UPSTREAM_DNS_SOURCE_REQUEST');
export const removeUpstreamDnsSourceFailure = createAction('REMOVE_UPSTREAM_DNS_SOURCE_FAILURE');
export const removeUpstreamDnsSourceSuccess = createAction('REMOVE_UPSTREAM_DNS_SOURCE_SUCCESS');

export const setUpstreamDnsSourceRequest = createAction('SET_UPSTREAM_DNS_SOURCE_REQUEST');
export const setUpstreamDnsSourceFailure = createAction('SET_UPSTREAM_DNS_SOURCE_FAILURE');
export const setUpstreamDnsSourceSuccess = createAction('SET_UPSTREAM_DNS_SOURCE_SUCCESS');

export const refreshUpstreamDnsSourcesRequest = createAction('REFRESH_UPSTREAM_DNS_SOURCES_REQUEST');
export const refreshUpstreamDnsSourcesFailure = createAction('REFRESH_UPSTREAM_DNS_SOURCES_FAILURE');
export const refreshUpstreamDnsSourcesSuccess = createAction('REFRESH_UPSTREAM_DNS_SOURCES_SUCCESS');

export const toggleUpstreamDnsSourceModal = createAction('TOGGLE_UPSTREAM_DNS_SOURCE_MODAL');

type UpstreamDnsSource = {
    id: number;
    name: string;
    url: string;
    enabled: boolean;
    rulesCount: number;
    lastUpdated: string;
};

const normalizeStatus = (status: any) => {
    const { sources = [] } = status;

    return {
        sources: normalizeFilters(sources),
    };
};

export const getUpstreamDnsSources = () => async (dispatch: any) => {
    dispatch(getUpstreamDnsSourcesRequest());

    try {
        const data = await apiClient.getUpstreamDnsSourcesStatus();
        dispatch(getUpstreamDnsSourcesSuccess(normalizeStatus(data)));
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(getUpstreamDnsSourcesFailure());
    }
};

export const addUpstreamDnsSource =
    (payload: { name: string; url: string }) =>
    async (dispatch: any, getState: any) => {
        dispatch(addUpstreamDnsSourceRequest());

        try {
            await apiClient.addUpstreamDnsSource(payload);
            dispatch(addUpstreamDnsSourceSuccess());

            if (getState().upstreamDnsSources.isModalOpen) {
                dispatch(toggleUpstreamDnsSourceModal());
            }

            dispatch(addSuccessToast('upstream_dns_source_added_successfully'));
            dispatch(getUpstreamDnsSources());
        } catch (error) {
            dispatch(addErrorToast({ error }));
            dispatch(addUpstreamDnsSourceFailure());
        }
    };

export const removeUpstreamDnsSource =
    (payload: { url: string }) =>
    async (dispatch: any) => {
        dispatch(removeUpstreamDnsSourceRequest());

        try {
            await apiClient.removeUpstreamDnsSource(payload);
            dispatch(removeUpstreamDnsSourceSuccess());
            dispatch(addSuccessToast('upstream_dns_source_removed_successfully'));
            dispatch(getUpstreamDnsSources());
        } catch (error) {
            dispatch(addErrorToast({ error }));
            dispatch(removeUpstreamDnsSourceFailure());
        }
    };

export const setUpstreamDnsSource =
    (
        currentUrl: string,
        payload: {
            name: string;
            url: string;
            enabled: boolean;
        },
        closeModal = false,
    ) =>
    async (dispatch: any, getState: any) => {
        dispatch(setUpstreamDnsSourceRequest());

        try {
            await apiClient.setUpstreamDnsSource({
                url: currentUrl,
                data: payload,
            });

            dispatch(setUpstreamDnsSourceSuccess());

            if (closeModal && getState().upstreamDnsSources.isModalOpen) {
                dispatch(toggleUpstreamDnsSourceModal());
            }

            dispatch(addSuccessToast('upstream_dns_source_updated'));
            dispatch(getUpstreamDnsSources());
        } catch (error) {
            dispatch(addErrorToast({ error }));
            dispatch(setUpstreamDnsSourceFailure());
        }
    };

export const toggleUpstreamDnsSource =
    (source: UpstreamDnsSource) =>
    async (dispatch: any) => {
        return dispatch(
            setUpstreamDnsSource(source.url, {
                name: source.name,
                url: source.url,
                enabled: !source.enabled,
            }),
        );
    };

export const refreshUpstreamDnsSources = () => async (dispatch: any) => {
    dispatch(refreshUpstreamDnsSourcesRequest());

    try {
        const data = await apiClient.refreshUpstreamDnsSources();
        dispatch(refreshUpstreamDnsSourcesSuccess());

        const updated = data?.updated || 0;
        if (updated > 0) {
            dispatch(addSuccessToast(i18next.t('list_updated', { count: updated })));
        } else {
            dispatch(addSuccessToast('all_lists_up_to_date_toast'));
        }

        dispatch(getUpstreamDnsSources());
    } catch (error) {
        dispatch(addErrorToast({ error }));
        dispatch(refreshUpstreamDnsSourcesFailure());
    }
};

