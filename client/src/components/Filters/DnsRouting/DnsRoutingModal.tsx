import React from 'react';
import ReactModal from 'react-modal';
import { useTranslation } from 'react-i18next';

import DnsRoutingForm from './DnsRoutingForm';
import '../../ui/Modal.css';

ReactModal.setAppElement('#root');

type DnsRoutingModalProps = {
    isOpen: boolean;
    isEdit: boolean;
    processing: boolean;
    initialValues?: {
        name: string;
        url: string;
    };
    onClose: () => void;
    onSubmit: (values: { name: string; url: string }) => void;
};

const DnsRoutingModal = ({ isOpen, isEdit, processing, initialValues, onClose, onSubmit }: DnsRoutingModalProps) => {
    const { t } = useTranslation();

    return (
        <ReactModal
            className="Modal__Bootstrap modal-dialog modal-dialog-centered"
            closeTimeoutMS={0}
            isOpen={isOpen}
            onRequestClose={onClose}>
            <div className="modal-content">
                <div className="modal-header">
                    <h4 className="modal-title">{isEdit ? t('dns_routing_edit') : t('dns_routing_new')}</h4>

                    <button type="button" className="close" onClick={onClose}>
                        <span className="sr-only">Close</span>
                    </button>
                </div>

                <DnsRoutingForm
                    initialValues={initialValues}
                    processing={processing}
                    onCancel={onClose}
                    onSubmit={onSubmit}
                />
            </div>
        </ReactModal>
    );
};

export default DnsRoutingModal;
