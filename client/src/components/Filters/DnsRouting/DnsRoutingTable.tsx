import React from 'react';
// @ts-expect-error FIXME: update react-table
import ReactTable from 'react-table';
import { Trans, useTranslation } from 'react-i18next';

import CellWrap from '../../ui/CellWrap';
import { formatDetailedDateTime } from '../../../helpers/helpers';
import { isValidAbsolutePath } from '../../../helpers/form';

type SourceRow = {
    id: number;
    name: string;
    url: string;
    enabled: boolean;
    rulesCount: number;
    lastUpdated: string;
};

type DnsRoutingTableProps = {
    data: SourceRow[];
    loading: boolean;
    processingSet: boolean;
    processingRemove: boolean;
    disabledByFile: boolean;
    onToggle: (source: SourceRow) => void;
    onEdit: (url: string) => void;
    onDelete: (url: string) => void;
};

const DnsRoutingTable = ({
    data,
    loading,
    processingSet,
    processingRemove,
    disabledByFile,
    onToggle,
    onEdit,
    onDelete,
}: DnsRoutingTableProps) => {
    const { t } = useTranslation();

    const renderDateCell = (row: any) => CellWrap(row, formatDetailedDateTime);

    const columns = [
        {
            Header: <Trans>enabled_table_header</Trans>,
            accessor: 'enabled',
            width: 120,
            className: 'text-center',
            resizable: false,
            Cell: ({ original }: any) => (
                <label className="checkbox">
                    <input
                        title={original.enabled ? t('upstream_dns_source_state_enabled') : t('disabled')}
                        type="checkbox"
                        className="checkbox__input"
                        disabled={processingSet || disabledByFile}
                        checked={original.enabled}
                        onChange={() => onToggle(original)}
                    />
                    <span className="checkbox__label" />
                </label>
            ),
        },
        {
            Header: <Trans>name_table_header</Trans>,
            accessor: 'name',
            minWidth: 170,
            Cell: CellWrap,
        },
        {
            Header: <Trans>source_label</Trans>,
            accessor: 'url',
            minWidth: 240,
            // eslint-disable-next-line react/prop-types
            Cell: ({ value }: any) => (
                <div className="logs__row">
                    {isValidAbsolutePath(value) ? (
                        value
                    ) : (
                        <a href={value} target="_blank" rel="noopener noreferrer" className="link logs__text">
                            {value}
                        </a>
                    )}
                </div>
            ),
        },
        {
            Header: <Trans>rules_count_table_header</Trans>,
            accessor: 'rulesCount',
            className: 'text-center',
            minWidth: 120,
            // eslint-disable-next-line react/prop-types
            Cell: (props: any) => props.value.toLocaleString(),
        },
        {
            Header: <Trans>last_time_updated_table_header</Trans>,
            accessor: 'lastUpdated',
            className: 'text-center',
            minWidth: 180,
            Cell: renderDateCell,
        },
        {
            Header: <Trans>actions_table_header</Trans>,
            accessor: 'actions',
            className: 'text-center',
            width: 100,
            sortable: false,
            resizable: false,
            Cell: ({ original }: any) => (
                <div className="logs__row logs__row--center">
                    <button
                        type="button"
                        className="btn btn-icon btn-outline-primary btn-sm mr-2"
                        title={t('edit_table_action')}
                        onClick={() => onEdit(original.url)}
                        disabled={disabledByFile || processingSet}>
                        <svg className="icons icon12">
                            <use xlinkHref="#edit" />
                        </svg>
                    </button>

                    <button
                        type="button"
                        className="btn btn-icon btn-outline-secondary btn-sm"
                        onClick={() => onDelete(original.url)}
                        title={t('delete_table_action')}
                        disabled={disabledByFile || processingRemove}>
                        <svg className="icons icon12">
                            <use xlinkHref="#delete" />
                        </svg>
                    </button>
                </div>
            ),
        },
    ];

    return (
        <ReactTable
            data={data}
            columns={columns}
            showPagination
            defaultPageSize={10}
            loading={loading}
            className="-striped -highlight card-table-overflow"
            minRows={6}
            ofText="/"
            previousText={t('previous_btn')}
            nextText={t('next_btn')}
            pageText={t('page_table_footer_text')}
            rowsText={t('rows_table_footer_text')}
            loadingText={t('loading_table_status')}
            noDataText={t('upstream_dns_sources_not_found')}
        />
    );
};

export default DnsRoutingTable;
