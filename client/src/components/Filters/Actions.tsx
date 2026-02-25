import React from 'react';
import { withTranslation, Trans } from 'react-i18next';

interface ActionsProps {
    handleAdd: (...args: unknown[]) => unknown;
    handleRefresh: (...args: unknown[]) => unknown;
    processingRefreshFilters: boolean;
    whitelist?: boolean;
    addButtonText?: string;
}

const Actions = ({ handleAdd, handleRefresh, processingRefreshFilters, whitelist, addButtonText }: ActionsProps) => {
    let addTextKey = whitelist ? 'add_allowlist' : 'add_blocklist';
    if (addButtonText) {
        addTextKey = addButtonText;
    }

    return (
        <div className="card-actions">
            <button className="btn btn-success btn-standard mr-2 btn-large mb-2" type="submit" onClick={handleAdd}>
                <Trans>{addTextKey}</Trans>
            </button>

            <button
                className="btn btn-primary btn-standard mb-2"
                type="submit"
                onClick={handleRefresh}
                disabled={processingRefreshFilters}>
                <Trans>check_updates_btn</Trans>
            </button>
        </div>
    );
};

export default withTranslation()(Actions);
