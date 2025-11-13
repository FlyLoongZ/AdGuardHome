import { connect } from 'react-redux';
import {
    getUpstreamDNSFilesStatus,
    addUpstreamDNSFile,
    removeUpstreamDNSFile,
    toggleUpstreamDNSFileStatus,
    toggleFilteringModal,
    refreshUpstreamDNSFiles,
    editUpstreamDNSFile,
} from '../actions/filtering';

import DnsUpstream from '../components/Filters/DnsUpstream';

const mapStateToProps = (state: any) => {
    const { filtering } = state;
    const props = { filtering };
    return props;
};

const mapDispatchToProps = {
    getUpstreamDNSFilesStatus,
    addUpstreamDNSFile,
    removeUpstreamDNSFile,
    toggleUpstreamDNSFileStatus,
    toggleFilteringModal,
    refreshUpstreamDNSFiles,
    editUpstreamDNSFile,
};

export default connect(mapStateToProps, mapDispatchToProps)(DnsUpstream);