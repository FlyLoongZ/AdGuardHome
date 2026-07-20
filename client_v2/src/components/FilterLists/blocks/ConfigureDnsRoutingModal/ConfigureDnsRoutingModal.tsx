import { createSignal, createEffect, untrack } from 'solid-js';

import intl from 'panel/common/intl';
import { Dialog } from 'panel/common/ui/Dialog/Dialog';
import { MODAL_TYPE } from 'panel/helpers/constants';
import { ModalWrapper } from 'panel/common/ui/ModalWrapper';
import { closeModal } from 'panel/stores/modals';
import theme from 'panel/lib/theme';
import { Button } from 'panel/common/ui/Button';
import { Input } from 'panel/common/controls/Input';
import { validatePath, validateRequiredValue } from 'panel/helpers/validators';
import {
    addUpstreamDnsSource,
    setUpstreamDnsSource,
    upstreamDnsSourcesState,
    type UpstreamDnsSource,
} from 'panel/stores/upstreamDnsSources';

type FormValues = {
    name: string;
    url: string;
    enabled?: boolean;
};

type ConfigureDnsRoutingModalIdType = 'ADD_DNS_ROUTING' | 'EDIT_DNS_ROUTING';

type Props = {
    modalId: ConfigureDnsRoutingModalIdType;
    sourceToEdit?: UpstreamDnsSource;
};

const getTitle = (modalId: ConfigureDnsRoutingModalIdType) => {
    if (modalId === MODAL_TYPE.EDIT_DNS_ROUTING) {
        return intl.getMessage('dns_routing_edit');
    }

    return intl.getMessage('dns_routing_new');
};

const getButtonText = (modalId: ConfigureDnsRoutingModalIdType) => {
    if (modalId === MODAL_TYPE.EDIT_DNS_ROUTING) {
        return intl.getMessage('save');
    }

    return intl.getMessage('add');
};

export const ConfigureDnsRoutingModal = (props: Props) => {
    const [name, setName] = createSignal(untrack(() => props.sourceToEdit?.name) ?? '');
    const [url, setUrl] = createSignal(untrack(() => props.sourceToEdit?.url) ?? '');
    const [nameError, setNameError] = createSignal<string | undefined>();
    const [urlError, setUrlError] = createSignal<string | undefined>();

    createEffect(() => {
        setName(props.sourceToEdit?.name ?? '');
        setUrl(props.sourceToEdit?.url ?? '');
    });

    const validateAndSetErrors = () => {
        const nameErr = validateRequiredValue(name());
        const urlErr = validateRequiredValue(url()) || validatePath(url());
        setNameError(nameErr || undefined);
        setUrlError(urlErr || undefined);
        return !nameErr && !urlErr;
    };

    const resetForm = () => {
        setName('');
        setUrl('');
        setNameError(undefined);
        setUrlError(undefined);
    };

    const handleCancel = () => {
        resetForm();
        closeModal();
    };

    const handleFormSubmit = async (e: Event) => {
        e.preventDefault();

        if (!validateAndSetErrors()) {
            return;
        }

        const values: FormValues = {
            name: name().trim(),
            url: url().trim(),
        };

        let success = false;

        switch (props.modalId) {
            case MODAL_TYPE.ADD_DNS_ROUTING: {
                success = await addUpstreamDnsSource(values);
                break;
            }
            case MODAL_TYPE.EDIT_DNS_ROUTING: {
                if (!props.sourceToEdit) {
                    break;
                }

                success = await setUpstreamDnsSource(props.sourceToEdit.url, {
                    ...values,
                    enabled: props.sourceToEdit.enabled,
                });
                break;
            }
            default: {
                break;
            }
        }

        if (success) {
            resetForm();
            closeModal();
        }
    };

    const isSubmitting = () =>
        upstreamDnsSourcesState.processingAdd || upstreamDnsSourcesState.processingSet;

    return (
        <ModalWrapper id={props.modalId}>
            <Dialog visible onClose={handleCancel} title={getTitle(props.modalId)}>
                <form onSubmit={handleFormSubmit}>
                    <div>
                        <div class={theme.form.group}>
                            <div class={theme.form.input}>
                                <Input
                                    type="text"
                                    id="dns_routing_name"
                                    data-testid="upstream_dns_sources_name"
                                    label={intl.getMessage('name_label')}
                                    placeholder={intl.getMessage('enter_name_hint')}
                                    value={name()}
                                    onChange={(e) =>
                                        setName((e.target as HTMLInputElement).value)
                                    }
                                    onBlur={validateAndSetErrors}
                                    errorMessage={nameError()}
                                />
                            </div>

                            <div class={theme.form.input}>
                                <Input
                                    type="text"
                                    id="dns_routing_url"
                                    data-testid="upstream_dns_sources_url"
                                    label={intl.getMessage('source_label')}
                                    placeholder={intl.getMessage('enter_url_or_path_hint')}
                                    value={url()}
                                    onChange={(e) => setUrl((e.target as HTMLInputElement).value)}
                                    onBlur={validateAndSetErrors}
                                    errorMessage={urlError()}
                                />
                            </div>

                            <div class={theme.dialog.description}>
                                {intl.getMessage('upstream_dns_sources_input_hint')}
                            </div>
                        </div>
                    </div>

                    <div class={theme.dialog.footer}>
                        <Button
                            type="submit"
                            id="dns_routing_save"
                            data-testid="upstream_dns_sources_save"
                            variant="primary"
                            size="small"
                            disabled={isSubmitting()}
                            class={theme.dialog.button}
                        >
                            {getButtonText(props.modalId)}
                        </Button>

                        <Button
                            type="button"
                            id="dns_routing_cancel"
                            variant="secondary"
                            size="small"
                            onClick={handleCancel}
                            class={theme.dialog.button}
                        >
                            {intl.getMessage('cancel')}
                        </Button>
                    </div>
                </form>
            </Dialog>
        </ModalWrapper>
    );
};
