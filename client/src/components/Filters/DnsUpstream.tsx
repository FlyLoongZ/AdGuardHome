import React, { Component } from 'react';
import { withTranslation } from 'react-i18next';

import PageTitle from '../ui/PageTitle';

import Card from '../ui/Card';
import Modal from './Modal';
import Actions from './Actions';
import Table from './Table';
import { MODAL_TYPE } from '../../helpers/constants';

import { getCurrentFilter } from '../../helpers/helpers';

import { FilteringData } from '../../initialState';

interface DnsUpstreamProps {
    getUpstreamDNSFilesStatus: (...args: unknown[]) => unknown;
    filtering: FilteringData;
    removeUpstreamDNSFile: (...args: unknown[]) => unknown;
    toggleUpstreamDNSFileStatus: (...args: unknown[]) => unknown;
    addUpstreamDNSFile: (...args: unknown[]) => unknown;
    toggleFilteringModal: (...args: unknown[]) => unknown;
    refreshUpstreamDNSFiles: (...args: unknown[]) => unknown;
    editUpstreamDNSFile: (...args: unknown[]) => unknown;
    t: (...args: unknown[]) => string;
}

class DnsUpstream extends Component<DnsUpstreamProps> {
    componentDidMount() {
        this.props.getUpstreamDNSFilesStatus();
    }

    handleSubmit = (values: any) => {
        const { modalFilterUrl, modalType } = this.props.filtering;

        switch (modalType) {
            case MODAL_TYPE.EDIT_FILTERS:
                this.props.editUpstreamDNSFile(modalFilterUrl, values);
                break;
            case MODAL_TYPE.ADD_FILTERS: {
                const { name, url } = values;

                this.props.addUpstreamDNSFile(url, name);
                break;
            }
            default:
                break;
        }
    };

    handleDelete = (url: any) => {
        if (window.confirm(this.props.t('list_confirm_delete'))) {
            this.props.removeUpstreamDNSFile(url);
        }
    };

    toggleFilter = (url: any, data: any) => {
        this.props.toggleUpstreamDNSFileStatus(url, data);
    };

    handleRefresh = () => {
        this.props.refreshUpstreamDNSFiles();
    };

    render() {
        const {
            t,

            toggleFilteringModal,

            addUpstreamDNSFile,

            filtering: {
                upstreamDNSFiles,
                isModalOpen,
                isFilterAdded,
                processingRefreshUpstreamDNSFiles,
                processingRemoveUpstreamDNSFile,
                processingAddUpstreamDNSFile,
                processingConfigUpstreamDNSFile,
                processingUpstreamDNSFiles,
                modalType,
                modalFilterUrl,
            },
        } = this.props;
        const currentFilterData = getCurrentFilter(modalFilterUrl, upstreamDNSFiles);
        const loading =
            processingConfigUpstreamDNSFile ||
            processingUpstreamDNSFiles ||
            processingAddUpstreamDNSFile ||
            processingRemoveUpstreamDNSFile ||
            processingRefreshUpstreamDNSFiles;

        return (
            <>
                <PageTitle title={t('dns_upstream_files')} subtitle={t('dns_upstream_files_desc')} />

                <div className="content">
                    <div className="row">
                        <div className="col-md-12">
                            <Card subtitle={t('dns_upstream_files_hint')}>
                                <Table
                                    filters={upstreamDNSFiles}
                                    loading={loading}
                                    processingConfigFilter={processingConfigUpstreamDNSFile}
                                    toggleFilteringModal={toggleFilteringModal}
                                    handleDelete={this.handleDelete}
                                    toggleFilter={this.toggleFilter}
                                    noDataText={t('no_upstreams_data_found')}
                                />

                                <Actions
                                    handleAdd={() => this.props.toggleFilteringModal({ type: MODAL_TYPE.ADD_FILTERS })}
                                    handleRefresh={this.handleRefresh}
                                    processingRefreshFilters={processingRefreshUpstreamDNSFiles}
                                    addButtonText="add_custom_list"
                                />
                            </Card>
                        </div>
                    </div>
                </div>

                <Modal
                    filters={upstreamDNSFiles}
                    isOpen={isModalOpen}
                    toggleFilteringModal={toggleFilteringModal}
                    addFilter={addUpstreamDNSFile}
                    isFilterAdded={isFilterAdded}
                    processingAddFilter={processingAddUpstreamDNSFile}
                    processingConfigFilter={processingConfigUpstreamDNSFile}
                    handleSubmit={this.handleSubmit}
                    modalType={modalType}
                    currentFilterData={currentFilterData}
                    title={t('dns_upstream_files')}
                    description={t('dns_upstream_files_hint')}
                />
            </>
        );
    }
}

export default withTranslation()(DnsUpstream);
