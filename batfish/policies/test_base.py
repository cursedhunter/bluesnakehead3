from pybfe.datamodel.policy import (
    STATUS_FAIL, STATUS_PASS
)
from pybatfish.datamodel.flow import HeaderConstraints
from pybatfish.datamodel.flow import PathConstraints
from pybatfish.datamodel.route import BgpRouteConstraints
import os
import re

from .test_utils import record_results
from .test_utils import write_to_csv_output


def exclude_vlan_loop_interface(interface):
    regex = "(^Vlan)|(^Loopback)"
    if re.search(regex, interface):
        return False
    else:
        return True


def test_no_undefined_refs(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.assert_no_undefined_references()

def test_no_duplicate_ips(bf):
    global e
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert no duplicate IP addresses are configured'

    ipOwn = bf.q.ipOwners(duplicatesOnly=True).answer().frame()
    dup_ips = ipOwn[ipOwn['Interface'].apply(
        lambda x: exclude_vlan_loop_interface(x))]

    try:
        assert len(dup_ips.index) == 0
        record_results(bf, status=STATUS_PASS,
                       message='No duplicate IP addresses present in the network')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='{} Found duplicate IP address assignment'.format(dup_ips))
        raise e


def test_no_illegal_mtu(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert that all MTUs are 1500 bytes'

    ans = bf.q.interfaceProperties(properties="MTU").answer().frame()
    bad_mtu = ans[ans.MTU < 1180]

    try:
        assert len(bad_mtu) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All interface MTUs are correct')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='{} Found interfaces with incorrect MTUs'.format(bad_mtu))
        raise e


def _illegal_bandwidth(interface, bandwidth):
    # interfaces like spine[swp23]
    if re.search("^spine", interface.hostname) and re.search(r"^swp\d+$", interface.interface):
        return bandwidth != 1000000000000
    # interfaces like leaf[swp23]
    elif re.search("^leaf", interface.hostname) and re.search(r"^swp\d+$", interface.interface):
        return bandwidth != 10000000000
    # interfaces like swp23s1
    elif re.search(r"^swp\d+s\d+$", interface.interface):
        return bandwidth != 250000000000
    # interfaces like eth0
    elif re.search(r"^eth\d+$", interface.interface):
        return bandwidth != 10000000000
    return False


def test_interface_bandwidth(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert that all interface bandwidth are correct'

    ans = bf.q.interfaceProperties(properties="Bandwidth").answer().frame()
    bad_bw = ans[ans.apply(lambda row: _illegal_bandwidth(
        row['Interface'], row['Bandwidth']), axis=1)]

    try:
        assert len(bad_bw) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All interface bandwidths are correct')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='{} Found interfaces with incorrect bandwidths'.format(bad_bw))
        raise e


def _illegal_speed(interface, bandwidth):
    # interfaces like spine[swp23]
    if re.search("^spine", interface.hostname) and re.search(r"^swp\d+$", interface.interface):
        return bandwidth != 1000000000000
    # interfaces like swp23s1
    elif re.search("^spine", interface.hostname) and re.search(r"^swp\d+s\d+$", interface.interface):
        return bandwidth != 250000000000
    return False


def test_interface_speed(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert that all interface speeds are correct'

    ans = bf.q.interfaceProperties(properties="Speed").answer().frame()
    bad_speed = ans[ans.apply(lambda row: _illegal_speed(
        row['Interface'], row['Speed']), axis=1)]

    try:
        assert len(bad_speed) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All interface speeds are correct')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='{} Found interfaces with incorrect speeds'.format(bad_speed))
        raise e


def test_proxy_arp(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert that proxy ARP is turned off on all interfaces'

    ans = bf.q.interfaceProperties(properties="Proxy_ARP").answer().frame()
    bad_speed = ans[ans.Proxy_ARP != False]

    try:
        assert len(bad_speed) == 0
        record_results(bf, status=STATUS_PASS,
                       message='Proxy ARP is off for all interfaces')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='{} Found interfaces with incorrect proxy ARP setting'.format(bad_speed))
        raise e


def test_mask_for_host_subnet(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert all host subnets are configured with a /24 netmask'

    # get ipAddress for all VLAN interfaces on all leaf routers
    tip = bf.q.ipOwners().answer().frame()
    leaf_tip = tip[(tip['Node'].str.contains('leaf'))]
    leaf_vlan_tip = tip[(tip['Node'].str.contains('leaf'))
                        & (tip['Interface'].str.contains('vlan'))]
    df = leaf_vlan_tip[leaf_vlan_tip['Mask'] != 24]

    try:
        assert len(df.index) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All host subnets have correct /24 mask')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Host-subnet mask is not /24 on following router-interface pairs:\n{}'.format(
                           df))
        raise e


# def test_dns_server(bf):
#     os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
#     bf.asserts.current_assertion = 'Assert all nodes have correct DNS server'

#     dns_servers = ['8.8.8.8']
#     dns = bf.q.nodeProperties(
#         properties='/DNS.*/').answer().frame()

#     df = dns[dns['DNS_Servers'].apply(lambda x: x != dns_servers)]
#     try:
#         assert len(df) == 0
#         record_results(bf, status=STATUS_PASS,
#                        message='All nodes have correct DNS server')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='Nodes with incorrect DNS server:\n{}'.format(df))
#         raise e


def test_ntp_server(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert all host subnets are configured with a /24 netmask'

    ntp_servers = ["poc-ntp.sjc.aristanetworks.com", '172.22.60.22']
    ntp = bf.q.nodeProperties(properties='/NTP.*/').answer().frame()

    df = ntp[ntp['NTP_Servers'].apply(lambda x: x in ntp_servers)]

    try:
        assert len(df) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All nodes have correct DNS server')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Nodes with incorrect DNS server:\n{}'.format(df))
        raise e

def test_no_unused_structures(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert no unused structures are configured'

    unused = bf.q.unusedStructures().answer().frame()
    write_to_csv_output(unused, "UnusedStructures")

    try:
        assert len(unused) == 0
        record_results(bf, status=STATUS_PASS,
                       message='No unused structures present in configuration')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Found unused structures:\n{}'.format(unused))
        raise e

def test_defined_structures(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Collect defined structures'

    result = bf.q.definedStructures().answer().frame()
    write_to_csv_output(result, "DefinedStructures")

    record_results(bf, status=STATUS_PASS,
                    message='Defined structures')

def test_ecmp(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert ECMP Multipath consistency'

    loopback_mp_consistency = bf.q.loopbackMultipathConsistency().answer().frame()
    denied_count = 0
    for elem in range(0, len(loopback_mp_consistency.Traces)):
        if loopback_mp_consistency.Traces[elem][0].disposition != "ACCEPTED":
            denied_count += 1

    write_to_csv_output(loopback_mp_consistency,"LoopbackMultipathConsistency")

    try:
        assert denied_count == 0
        record_results(bf, status=STATUS_PASS,
                       message='ECMP loopback multipath consistency passed')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Found ECMP loopback multipath consistency issues:\n{}'.format(loopback_mp_consistency))
        raise e

def test_acl_filter_line_reachability(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert ACL Filter Line Reachability'

    unreachableLines = bf.q.filterLineReachability().answer().frame()

    try:
        assert len(unreachableLines) == 0
        record_results(bf, status=STATUS_PASS,
                       message='ACL Filter Line Reachability passed')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Found ACL Filter Line Reachability issues:\n{}'.format(unreachableLines))
        raise e

def test_routing(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Collect Routing Data'

    routes = bf.q.routes().answer().frame()
    write_to_csv_output(routes, "Routes")

    try:
        assert len(routes) != 0
        record_results(bf, status=STATUS_PASS,
                       message='Routing check passed: {} routes'.format(len(routes)))
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='No routes found')
        raise e

def test_leaf_spine_bgp_peers(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert correct number of leaf-spine BGP peers'

    bgp_peer = bf.q.bgpPeerConfiguration().answer().frame()
    write_to_csv_output(bgp_peer, "BGP_Peers")

    leaf_bgp_peer = bf.q.bgpPeerConfiguration(nodes='/leaf.*/', properties='/Local_IP/').answer().frame()
    write_to_csv_output(leaf_bgp_peer, "Leaf_BGP_Peers")

    nodes_list = set(leaf_bgp_peer['Node'])

    for node in nodes_list:
        print("Leaf {} has {} peers".format(node, len(leaf_bgp_peer[leaf_bgp_peer['Node']==node])))
        # if len(bgpPeer[bgpPeer['Node']==node]) != num_spines:
        #    bad_leaf.append(node)

    record_results(bf, status=STATUS_PASS,
                   message='BGP Peers check passed')
    # try:
    #     assert len(routes) != 0
    #     record_results(bf, status=STATUS_PASS,
    #                    message='Routing check passed: {} routes'.format(len(routes)))
    # except Exception as e:
    #     record_results(bf, status=STATUS_FAIL,
    #                    message='No routes found')
    #     raise e



def test_init_issues(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert No Init Issues'

    init_issues = bf.q.initIssues().answer().frame()
    found_issues = init_issues.loc[init_issues['Type'] == 'Convert warning (redflag)']
    write_to_csv_output(init_issues, "Init_Issues")

    try:
        assert len(found_issues) == 0
        record_results(bf, status=STATUS_PASS,
                       message='No Init Issues')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='Found Init issues:\n{}'.format(found_issues))
        raise e

def test_parse_warnings(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"

    parse_warning = bf.q.parseWarning().answer().frame()

    for elem in parse_warning:
        print(elem)

    write_to_csv_output(parse_warning, "Parse_Warnings")
    record_results(bf, status=STATUS_FAIL,
                   message='Collected Parse Warnings')

def test_file_parse(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"

    file_parse = bf.q.fileParseStatus().answer().frame()

    write_to_csv_output(file_parse, "File_Parse")
    record_results(bf, status=STATUS_PASS,
                   message='Collected File Parse results')

def test_layer1_provided_topology(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"

    layer1_topology = bf.q.userProvidedLayer1Edges().answer().frame()
    write_to_csv_output(layer1_topology, "Layer1_Topology_Provided")

def test_search_route_policies(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert all BGP sessions are established'

    result = bf.q.searchRoutePolicies(nodes='dc1-pod1-leaf4a', policies='RM-CONN-2-BGP', inputConstraints=BgpRouteConstraints(prefix=["10.0.100.0/24", "172.16.0.0/28:28-32", "192.168.0.0/16:16-32"]), action='permit').answer().frame()
    write_to_csv_output(result, "SearchRoutePolicies")

def test_bgp_rib(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'BGP RIB'

    result = bf.q.bgpRib().answer().frame()
    write_to_csv_output(result, "bgpRIB")

def test_bgp_sessions_up(bf):
    os.environ['bf_policy_name'] = "Base configuration Hygiene Policies"
    bf.asserts.current_assertion = 'Assert all BGP sessions are established'

    leaf_bgp_sess = bf.q.bgpSessionStatus(nodes='LEAF.*').answer().frame()
    df_leaf = leaf_bgp_sess[(leaf_bgp_sess['Address_Families'].apply(lambda x: 'IPV4_UNICAST' in x)) & (
        leaf_bgp_sess['Established_Status'] != 'ESTABLISHED')]
    write_to_csv_output(leaf_bgp_sess, "LeafBgpSessions")

    spine_bgp_sess = bf.q.bgpSessionStatus(nodes='SPINE.*').answer().frame()
    df_spine = spine_bgp_sess[(spine_bgp_sess['Address_Families'].apply(lambda x: 'IPV4_UNICAST' in x)) & (
        spine_bgp_sess['Established_Status'] != 'ESTABLISHED')]
    write_to_csv_output(spine_bgp_sess, "SpineBgpSessions")

    try:
        assert len(df_leaf) == 0
        assert len(df_spine) == 0
        record_results(bf, status=STATUS_PASS,
                       message='All BGP sessions are established')
    except Exception as e:
        record_results(bf, status=STATUS_FAIL,
                       message='BGP sessions are not established:\n{} \n{}'.format(df_leaf, df_spine))
        raise e
