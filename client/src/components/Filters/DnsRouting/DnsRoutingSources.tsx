import React, { useEffect, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import { shallowEqual, useDispatch, useSelector } from 'react-redux';

import Card from '../../ui/Card';
import { RootState } from '../../../initialState';
import { getDnsConfig } from '../../../actions/dnsConfig';
import {
    addUpstreamDnsSource,
    getUpstreamDnsSources,
    refreshUpstreamDnsSources,
    removeUpstreamDnsSource,
    setUpstreamDnsSource,
    toggleUpstreamDnsSource,
    toggleUpstreamDnsSourceModal,
} from '../../../actions/upstreamDnsSources';
import DnsRoutingTable from './DnsRoutingTable';
import DnsRoutingModal from './DnsRoutingModal';

type DnsRoutingSourcesProps = {
    standalone?: boolean;
};

const DnsRoutingSources = ({ standalone = false }: DnsRoutingSourcesProps) => {
    const { t } = useTranslation();
    const dispatch = useDispatch();

    const {
        sources,
        processing,
        processingAdd,
        processingRemove,
        processingSet,
        processingRefresh,
        isModalOpen,
        selectedSourceUrl,
    } = useSelector((state: RootState) => state.upstreamDnsSources, shallowEqual);

    const { upstream_dns_file: upstreamDnsFile, processingGetConfig, loaded } = useSelector(
        (state: RootState) => state.dnsConfig,
        shallowEqual,
    );

    const selectedSource = useMemo(() => sources.find((source: any) => source.url === selectedSourceUrl), [
        selectedSourceUrl,
        sources,
    ]);

    const isEdit = Boolean(selectedSource);
    const isDnsConfigPending = !loaded || processingGetConfig;
    const isLegacyFileMode = isDnsConfigPending || Boolean(upstreamDnsFile);

    useEffect(() => {
        dispatch(getUpstreamDnsSources());
        dispatch(getDnsConfig());
    }, []);

    const closeModal = () => {
        dispatch(toggleUpstreamDnsSourceModal());
    };

    const handleOpenNew = () => {
        dispatch(toggleUpstreamDnsSourceModal({ url: '' }));
    };

    const handleOpenEdit = (url: string) => {
        dispatch(toggleUpstreamDnsSourceModal({ url }));
    };

    const handleDelete = (url: string) => {
        if (window.confirm(t('upstream_dns_source_confirm_delete'))) {
            dispatch(removeUpstreamDnsSource({ url }));
        }
    };

    const handleToggle = (source: any) => {
        dispatch(toggleUpstreamDnsSource(source));
    };

    const handleRefresh = () => {
        dispatch(refreshUpstreamDnsSources());
    };

    const handleSubmit = (values: { name: string; url: string }) => {
        if (isEdit && selectedSource) {
            dispatch(
                setUpstreamDnsSource(
                    selectedSource.url,
                    {
                        ...values,
                        enabled: selectedSource.enabled,
                    },
                    true,
                ),
            );

            return;
        }

        dispatch(addUpstreamDnsSource(values));
    };

    const loading = processing || processingAdd || processingRemove || processingSet || processingRefresh;
    const modalProcessing = processingAdd || processingSet;

    const content = (
        <>
            {isLegacyFileMode && (
                <div className="alert alert-warning mb-4" role="alert">
                    {t('upstream_dns_sources_configured_in_file_warning', { path: upstreamDnsFile })}
                </div>
            )}

            <DnsRoutingTable
                data={sources}
                loading={loading}
                processingSet={processingSet}
                processingRemove={processingRemove}
                disabledByFile={isLegacyFileMode}
                onToggle={handleToggle}
                onEdit={handleOpenEdit}
                onDelete={handleDelete}
            />

            <div className="card-actions">
                <button
                    className="btn btn-success btn-standard mr-2 btn-large mb-2"
                    type="button"
                    onClick={handleOpenNew}
                    disabled={isLegacyFileMode || processingAdd || processingSet}>
                    {t('dns_routing_add')}
                </button>

                <button
                    className="btn btn-primary btn-standard mb-2"
                    type="button"
                    onClick={handleRefresh}
                    disabled={isLegacyFileMode || processingRefresh}>
                    {t('check_updates_btn')}
                </button>
            </div>

            <DnsRoutingModal
                isOpen={isModalOpen}
                isEdit={isEdit}
                processing={modalProcessing}
                initialValues={selectedSource}
                onClose={closeModal}
                onSubmit={handleSubmit}
            />
        </>
    );

    if (standalone) {
        return content;
    }

    return <Card title={t('dns_routing')} subtitle={t('dns_routing_desc')} bodyType="card-body box-body--settings">{content}</Card>;
};

export default DnsRoutingSources;
