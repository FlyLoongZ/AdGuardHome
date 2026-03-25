import React from 'react';
import { Controller, useForm } from 'react-hook-form';
import { useTranslation } from 'react-i18next';

import { Input } from '../../ui/Controls/Input';
import { validatePath, validateRequiredValue } from '../../../helpers/validators';

type SourceFormValues = {
    name: string;
    url: string;
};

type DnsRoutingFormProps = {
    initialValues?: Partial<SourceFormValues>;
    processing: boolean;
    onCancel: () => void;
    onSubmit: (values: SourceFormValues) => void;
};

const DnsRoutingForm = ({ initialValues, processing, onCancel, onSubmit }: DnsRoutingFormProps) => {
    const { t } = useTranslation();

    const {
        control,
        handleSubmit,
        formState: { isSubmitting },
    } = useForm<SourceFormValues>({
        defaultValues: {
            name: initialValues?.name || '',
            url: initialValues?.url || '',
        },
        mode: 'onBlur',
    });

    return (
        <form onSubmit={handleSubmit(onSubmit)}>
            <div className="modal-body modal-body--filters">
                <div className="form__group">
                    <Controller
                        name="name"
                        control={control}
                        rules={{ validate: validateRequiredValue }}
                        render={({ field, fieldState }) => (
                            <Input
                                {...field}
                                type="text"
                                data-testid="upstream_dns_sources_name"
                                placeholder={t('enter_name_hint')}
                                error={fieldState.error?.message}
                                trimOnBlur
                            />
                        )}
                    />
                </div>

                <div className="form__group">
                    <Controller
                        name="url"
                        control={control}
                        rules={{ validate: { validateRequiredValue, validatePath } }}
                        render={({ field, fieldState }) => (
                            <Input
                                {...field}
                                type="text"
                                data-testid="upstream_dns_sources_url"
                                placeholder={t('enter_url_or_path_hint')}
                                error={fieldState.error?.message}
                                trimOnBlur
                            />
                        )}
                    />
                </div>

                <div className="form__description">{t('upstream_dns_sources_input_hint')}</div>
            </div>

            <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={onCancel}>
                    {t('cancel_btn')}
                </button>

                <button
                    type="submit"
                    data-testid="upstream_dns_sources_save"
                    className="btn btn-success"
                    disabled={processing || isSubmitting}>
                    {t('save_btn')}
                </button>
            </div>
        </form>
    );
};

export default DnsRoutingForm;

