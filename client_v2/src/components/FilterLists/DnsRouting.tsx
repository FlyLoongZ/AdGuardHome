import { createSignal, createMemo, createEffect, Show, onMount } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { MODAL_TYPE } from 'panel/helpers/constants';
import theme from 'panel/lib/theme';
import { Icon } from 'panel/common/ui/Icon';
import { PageLoader } from 'panel/common/ui/Loader';
import { PlusButton } from 'panel/common/ui/PlusButton';
import { Banner } from 'panel/common/ui/Banner';
import { openModal } from 'panel/stores/modals';
import { getDnsConfig, dnsConfigState } from 'panel/stores/dnsConfig';
import {
    getUpstreamDnsSources,
    refreshUpstreamDnsSources,
    toggleUpstreamDnsSource,
    upstreamDnsSourcesState,
    type UpstreamDnsSource,
} from 'panel/stores/upstreamDnsSources';

import { ConfigureDnsRoutingModal } from './blocks/ConfigureDnsRoutingModal';
import { DeleteDnsRoutingModal } from './blocks/DeleteDnsRoutingModal';
import { DnsRoutingTable } from './blocks/DnsRoutingTable';

import s from './FilterLists.module.pcss';

export const DnsRouting = () => {
    const [currentSource, setCurrentSource] = createSignal<UpstreamDnsSource | null>(null);
    const [isInitialLoad, setIsInitialLoad] = createSignal(true);

    onMount(() => {
        getUpstreamDnsSources();
        getDnsConfig();
    });

    createEffect(() => {
        const loading =
            upstreamDnsSourcesState.processing || dnsConfigState.processingGetConfig;
        if (!loading && isInitialLoad()) {
            setIsInitialLoad(false);
        }
    });

    const isDataReady = createMemo(() => {
        const loading =
            upstreamDnsSourcesState.processing || dnsConfigState.processingGetConfig;
        return loading && isInitialLoad();
    });

    const isLegacyFileMode = createMemo(() => Boolean(dnsConfigState.upstream_dns_file));
    const actionsDisabled = createMemo(
        () => dnsConfigState.processingGetConfig || isLegacyFileMode(),
    );

    const handleRefresh = () => {
        refreshUpstreamDnsSources();
    };

    const openAddModal = () => {
        setCurrentSource(null);
        openModal(MODAL_TYPE.ADD_DNS_ROUTING);
    };

    const openEditModal = (source: UpstreamDnsSource) => {
        setCurrentSource(source);
        openModal(MODAL_TYPE.EDIT_DNS_ROUTING);
    };

    const openDeleteModal = (source: UpstreamDnsSource) => {
        setCurrentSource(source);
        openModal(MODAL_TYPE.DELETE_DNS_ROUTING);
    };

    const handleToggle = (source: UpstreamDnsSource) => {
        toggleUpstreamDnsSource(source);
    };

    return (
        <div class={theme.layout.container}>
            <div class={theme.layout.containerIn}>
                <Show
                    when={isDataReady()}
                    fallback={
                        <>
                            <div class={s.header}>
                                <h1
                                    class={cn(
                                        theme.layout.title,
                                        theme.title.h4,
                                        theme.title.h3_tablet,
                                    )}
                                >
                                    {intl.getMessage('dns_routing')}
                                </h1>

                                <button
                                    type="button"
                                    onClick={handleRefresh}
                                    disabled={
                                        actionsDisabled() ||
                                        upstreamDnsSourcesState.processingRefresh
                                    }
                                    class={cn(s.button, s.button_checkUpdates)}
                                >
                                    <Icon icon="refresh" color="green" />
                                    <span class={s.labelDesktop}>
                                        {intl.getMessage('check_updates_btn')}
                                    </span>
                                </button>
                            </div>

                            <div class={s.desc}>{intl.getMessage('dns_routing_desc')}</div>

                            <Show when={isLegacyFileMode()}>
                                <div class={s.group}>
                                    <Banner
                                        variant="warning"
                                        message={intl.getMessage(
                                            'upstream_dns_sources_configured_in_file_warning',
                                            { path: dnsConfigState.upstream_dns_file },
                                        )}
                                        data-testid="dns-routing-file-warning"
                                    />
                                </div>
                            </Show>

                            <div class={cn(s.group, s.buttonGroup)}>
                                <PlusButton
                                    onClick={openAddModal}
                                    disabled={
                                        actionsDisabled() ||
                                        upstreamDnsSourcesState.processingAdd ||
                                        upstreamDnsSourcesState.processingSet
                                    }
                                >
                                    {intl.getMessage('dns_routing_add')}
                                </PlusButton>
                            </div>

                            <div class={cn(s.group, s.tableGroup)}>
                                <DnsRoutingTable
                                    sources={upstreamDnsSourcesState.sources}
                                    processingSet={upstreamDnsSourcesState.processingSet}
                                    processingRemove={upstreamDnsSourcesState.processingRemove}
                                    disabledByFile={actionsDisabled()}
                                    onToggle={handleToggle}
                                    onEdit={openEditModal}
                                    onDelete={openDeleteModal}
                                />
                            </div>

                            <ConfigureDnsRoutingModal modalId={MODAL_TYPE.ADD_DNS_ROUTING} />

                            <ConfigureDnsRoutingModal
                                modalId={MODAL_TYPE.EDIT_DNS_ROUTING}
                                sourceToEdit={currentSource() ?? undefined}
                            />

                            <DeleteDnsRoutingModal
                                sourceToDelete={currentSource()}
                                setSourceToDelete={setCurrentSource}
                            />
                        </>
                    }
                >
                    <PageLoader />
                </Show>
            </div>
        </div>
    );
};
