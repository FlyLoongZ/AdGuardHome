import { handleActions } from 'redux-actions';

import * as actions from '../actions/upstreamDnsSources';

const upstreamDnsSources = handleActions(
    {
        [actions.getUpstreamDnsSourcesRequest.toString()]: (state: any) => ({
            ...state,
            processing: true,
        }),
        [actions.getUpstreamDnsSourcesFailure.toString()]: (state: any) => ({
            ...state,
            processing: false,
        }),
        [actions.getUpstreamDnsSourcesSuccess.toString()]: (state: any, { payload }: any) => ({
            ...state,
            ...payload,
            processing: false,
        }),

        [actions.addUpstreamDnsSourceRequest.toString()]: (state: any) => ({
            ...state,
            processingAdd: true,
        }),
        [actions.addUpstreamDnsSourceFailure.toString()]: (state: any) => ({
            ...state,
            processingAdd: false,
        }),
        [actions.addUpstreamDnsSourceSuccess.toString()]: (state: any) => ({
            ...state,
            processingAdd: false,
        }),

        [actions.removeUpstreamDnsSourceRequest.toString()]: (state: any) => ({
            ...state,
            processingRemove: true,
        }),
        [actions.removeUpstreamDnsSourceFailure.toString()]: (state: any) => ({
            ...state,
            processingRemove: false,
        }),
        [actions.removeUpstreamDnsSourceSuccess.toString()]: (state: any) => ({
            ...state,
            processingRemove: false,
        }),

        [actions.setUpstreamDnsSourceRequest.toString()]: (state: any) => ({
            ...state,
            processingSet: true,
        }),
        [actions.setUpstreamDnsSourceFailure.toString()]: (state: any) => ({
            ...state,
            processingSet: false,
        }),
        [actions.setUpstreamDnsSourceSuccess.toString()]: (state: any) => ({
            ...state,
            processingSet: false,
        }),

        [actions.refreshUpstreamDnsSourcesRequest.toString()]: (state: any) => ({
            ...state,
            processingRefresh: true,
        }),
        [actions.refreshUpstreamDnsSourcesFailure.toString()]: (state: any) => ({
            ...state,
            processingRefresh: false,
        }),
        [actions.refreshUpstreamDnsSourcesSuccess.toString()]: (state: any) => ({
            ...state,
            processingRefresh: false,
        }),

        [actions.toggleUpstreamDnsSourceModal.toString()]: (state: any, { payload }: any) => {
            if (payload) {
                return {
                    ...state,
                    isModalOpen: !state.isModalOpen,
                    selectedSourceUrl: payload.url || '',
                };
            }

            return {
                ...state,
                isModalOpen: !state.isModalOpen,
                selectedSourceUrl: '',
            };
        },
    },
    {
        processing: false,
        processingAdd: false,
        processingRemove: false,
        processingSet: false,
        processingRefresh: false,
        isModalOpen: false,
        selectedSourceUrl: '',
        sources: [],
    },
);

export default upstreamDnsSources;

