import React from 'react';
import { withTranslation } from 'react-i18next';

import PageTitle from '../ui/PageTitle';
import Card from '../ui/Card';
import DnsRoutingSources from './DnsRouting/DnsRoutingSources';

interface DnsRoutingProps {
    t: (...args: unknown[]) => string;
}

const DnsRouting = ({ t }: DnsRoutingProps) => (
    <>
        <PageTitle title={t('dns_routing')} subtitle={t('dns_routing_desc')} />

        <div className="content">
            <div className="row">
                <div className="col-md-12">
                    <Card>
                        <DnsRoutingSources standalone />
                    </Card>
                </div>
            </div>
        </div>
    </>
);

export default withTranslation()(DnsRouting);
