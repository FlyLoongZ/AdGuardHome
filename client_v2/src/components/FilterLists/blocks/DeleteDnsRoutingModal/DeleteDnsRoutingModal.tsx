import { Show } from 'solid-js';

import intl from 'panel/common/intl';
import { ConfirmDialog } from 'panel/common/ui/ConfirmDialog';
import { MODAL_TYPE } from 'panel/helpers/constants';
import { ModalWrapper } from 'panel/common/ui/ModalWrapper';
import { closeModal } from 'panel/stores/modals';
import {
    removeUpstreamDnsSource,
    upstreamDnsSourcesState,
    type UpstreamDnsSource,
} from 'panel/stores/upstreamDnsSources';

type Props = {
    sourceToDelete: UpstreamDnsSource | null;
    setSourceToDelete: (value: UpstreamDnsSource | null) => void;
};

export const DeleteDnsRoutingModal = (props: Props) => {
    const handleDeleteClose = () => {
        props.setSourceToDelete(null);
        closeModal();
    };

    const handleDeleteConfirm = async () => {
        if (!props.sourceToDelete) {
            return;
        }

        const success = await removeUpstreamDnsSource(props.sourceToDelete.url);
        if (success) {
            handleDeleteClose();
        }
    };

    return (
        <Show when={props.sourceToDelete?.url}>
            <ModalWrapper id={MODAL_TYPE.DELETE_DNS_ROUTING}>
                <ConfirmDialog
                    onClose={handleDeleteClose}
                    onConfirm={handleDeleteConfirm}
                    submitDisabled={upstreamDnsSourcesState.processingRemove}
                    buttonText={intl.getMessage('remove')}
                    cancelText={intl.getMessage('cancel')}
                    title={intl.getMessage('dns_routing')}
                    text={intl.getMessage('upstream_dns_source_confirm_delete')}
                    buttonVariant="danger"
                />
            </ModalWrapper>
        </Show>
    );
};
