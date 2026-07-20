import { createSignal, createMemo } from 'solid-js';
import cn from 'clsx';

import intl from 'panel/common/intl';
import { formatShortDateTime } from 'panel/helpers/helpers';
import { isValidAbsolutePath } from 'panel/helpers/form';
import { LOCAL_STORAGE_KEYS, LocalStorageHelper } from 'panel/helpers/localStorageHelper';
import { Table, type TableColumn } from 'panel/common/ui/Table';
import { Switch } from 'panel/common/controls/Switch';
import { Icon } from 'panel/common/ui/Icon';
import { SortSelect } from 'panel/common/ui/SortSelect';
import theme from 'panel/lib/theme';
import type { UpstreamDnsSource } from 'panel/stores/upstreamDnsSources';

import s from '../ListsTable/ListsTable.module.pcss';

type Props = {
    sources: UpstreamDnsSource[];
    processingSet: boolean;
    processingRemove: boolean;
    disabledByFile: boolean;
    onToggle: (source: UpstreamDnsSource) => void;
    onEdit: (source: UpstreamDnsSource) => void;
    onDelete: (source: UpstreamDnsSource) => void;
};

export const DnsRoutingTable = (props: Props) => {
    const [sortDirection, setSortDirection] = createSignal<'asc' | 'desc'>('asc');

    const pageSize = createMemo(
        () => LocalStorageHelper.getItem(LOCAL_STORAGE_KEYS.DNS_ROUTING_PAGE_SIZE) || undefined,
    );

    const sortedSources = createMemo(() => {
        const items = [...(props.sources || [])];
        const direction = sortDirection();

        items.sort((a, b) => {
            const aName = (a.name || '').toLowerCase();
            const bName = (b.name || '').toLowerCase();

            if (aName < bName) {
                return direction === 'asc' ? -1 : 1;
            }

            if (aName > bName) {
                return direction === 'asc' ? 1 : -1;
            }

            return 0;
        });

        return items;
    });

    const columns = createMemo<TableColumn<UpstreamDnsSource>[]>(() => [
        {
            key: 'enabled',
            header: {
                text: '',
                className: s.headerCell,
            },
            accessor: 'enabled',
            sortable: false,
            width: 64,
            className: s.cellNameToggleOuter,
            render: (_value: boolean, row: UpstreamDnsSource) => {
                const { name, url, enabled } = row;
                const id = `dns_routing_${url}`;

                return (
                    <div class={theme.table.cell}>
                        <span class={s.cellNameLabel}>{name}</span>

                        <div class={s.cellValueToggle}>
                            <Switch
                                id={id}
                                checked={enabled}
                                onChange={() => props.onToggle(row)}
                                disabled={props.processingSet || props.disabledByFile}
                            />
                        </div>
                    </div>
                );
            },
        },
        {
            key: 'name',
            header: {
                text: intl.getMessage('name_label'),
                className: s.headerCell,
            },
            accessor: 'name',
            sortable: true,
            className: s.nameDesktopOnly,
            render: (value: string, row: UpstreamDnsSource) => (
                <div class={theme.table.cell}>
                    <span class={theme.table.cellLabel}>{intl.getMessage('name_label')}</span>

                    <div class={theme.table.cellValueText}>
                        <span class={theme.common.textOverflow}>{value}</span>
                        {row.lastError ? (
                            <span
                                class={cn(theme.common.textOverflow, s.errorText)}
                                title={row.lastError}
                            >
                                {row.lastError}
                            </span>
                        ) : null}
                    </div>
                </div>
            ),
        },
        {
            key: 'url',
            header: {
                text: intl.getMessage('source_label'),
                className: s.headerCell,
            },
            accessor: 'url',
            sortable: true,
            render: (value: string) => (
                <div class={theme.table.cell}>
                    <span class={theme.table.cellLabel}>{intl.getMessage('source_label')}</span>

                    <div class={theme.table.cellValueText}>
                        {isValidAbsolutePath(value) ? (
                            <span class={theme.common.textOverflow}>{value}</span>
                        ) : (
                            <a
                                href={value}
                                class={cn(theme.link.link, theme.common.textOverflow)}
                                target="_blank"
                                rel="noopener noreferrer nofollow"
                            >
                                {value}
                            </a>
                        )}

                        <button
                            type="button"
                            class={s.copyButton}
                            onClick={() => navigator.clipboard.writeText(value)}
                            aria-label={intl.getMessage('copy')}
                        >
                            <Icon icon="copy" color="green" />
                        </button>
                    </div>
                </div>
            ),
        },
        {
            key: 'rulesCount',
            header: {
                text: intl.getMessage('rules_label'),
                className: s.headerCell,
            },
            accessor: 'rulesCount',
            sortable: true,
            render: (value: number) => (
                <div class={theme.table.cell}>
                    <span class={theme.table.cellLabel}>{intl.getMessage('rules_label')}</span>

                    <div class={theme.table.cellValueText}>
                        <span>{value?.toLocaleString() || 0}</span>
                    </div>
                </div>
            ),
        },
        {
            key: 'lastUpdated',
            header: {
                text: intl.getMessage('last_updated_label'),
                className: s.headerCell,
            },
            accessor: 'lastUpdated',
            sortable: true,
            render: (value: string) => {
                const result = formatShortDateTime(value);

                return (
                    <div class={theme.table.cell}>
                        <span class={theme.table.cellLabel}>
                            {intl.getMessage('last_updated_label')}
                        </span>

                        <div class={theme.table.cellValueText}>
                            <span>{result}</span>
                        </div>
                    </div>
                );
            },
        },
        {
            key: 'actions',
            header: {
                text: '',
                className: s.headerCell,
            },
            accessor: 'url',
            sortable: false,
            width: 80,
            render: (_value: string, row: UpstreamDnsSource) => (
                <div class={theme.table.cell}>
                    <div class={theme.table.cellValue}>
                        <div class={theme.table.cellActions}>
                            <button
                                type="button"
                                onClick={() => props.onEdit(row)}
                                disabled={props.disabledByFile || props.processingSet}
                                class={theme.table.action}
                                title={intl.getMessage('edit_table_action')}
                                aria-label={intl.getMessage('edit_table_action')}
                                data-table-action
                            >
                                <Icon icon="edit" color="gray" />
                                <span class={theme.table.actionLabel}>
                                    {intl.getMessage('edit_table_action')}
                                </span>
                            </button>

                            <button
                                type="button"
                                onClick={() => props.onDelete(row)}
                                disabled={props.disabledByFile || props.processingRemove}
                                class={cn(theme.table.action, theme.table.action_danger)}
                                title={intl.getMessage('delete_table_action')}
                                aria-label={intl.getMessage('delete_table_action')}
                                data-table-action
                            >
                                <Icon icon="delete" color="red" />
                                <span class={theme.table.actionLabel}>
                                    {intl.getMessage('delete_table_action')}
                                </span>
                            </button>
                        </div>
                    </div>
                </div>
            ),
        },
    ]);

    const handlePageSizeChange = (newSize: number) => {
        LocalStorageHelper.setItem(LOCAL_STORAGE_KEYS.DNS_ROUTING_PAGE_SIZE, newSize);
    };

    const emptyTableContent = () => (
        <div class={s.emptyTableContent}>
            <Icon icon="not_found_search" color="gray" class={s.emptyTableIcon} />

            <div class={cn(theme.text.t3, s.emptyTableDesc)}>
                {intl.getMessage('dns_routing_empty')}
            </div>
        </div>
    );

    return (
        <>
            <div class={cn(theme.pagination.wrapper, s.sortDropdownMobile)}>
                <SortSelect value={sortDirection()} onChange={setSortDirection} />
            </div>

            <Table<UpstreamDnsSource>
                data={sortedSources()}
                class={s.table}
                columns={columns()}
                emptyTable={emptyTableContent()}
                pageSize={pageSize()}
                onPageSizeChange={handlePageSizeChange}
            />
        </>
    );
};
