from pybfe.datamodel.policy import (
    STATUS_FAIL, STATUS_PASS
)

import os
from .test_utils import record_results, write_to_csv_output
from collections import defaultdict
from pybatfish.datamodel.flow import HeaderConstraints
import pandas as pd

# def test_no_l2_vnis_empty_flood_list(bf):
#     """Check if any VNIs have empty flood lists."""
#     os.environ['bf_policy_name'] = "No L2 VNI with empty flood list"
#     bf.asserts.current_assertion = 'Assert no L2 VNIs have an empty flood list'

#     l2_vnis = bf.q.vxlanVniProperties().answer().frame()

#     empty_flood = l2_vnis[(l2_vnis['VLAN'].notnull()) & (
#         l2_vnis['VTEP_Flood_List'].apply(lambda x: not x))]
#     df = empty_flood[['Node', 'VRF', 'VNI']] 
#     write_to_csv_output(l2_vnis, "L2VNIs")
#     write_to_csv_output(df, "EmptyFloodList")

#     try:
#         assert df.empty == True
#         record_results(bf, status=STATUS_PASS,
#                        message='No L2 VNIs with empty flood list:\n{}'.format(df))
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='Found L2 VNIs with an empty flood list:\n{}'.format(df))
#         raise e

# def test_l3_vni_rds(bf):
#     """Assert all L3 VNIs used router-id as the route-distinguisher"."""
#     os.environ['bf_policy_name'] = "Unique L3 VNI RDs"
#     bf.asserts.current_assertion = 'Assert all L3 VNIs used router-id as the route-distinguisher"'

#     l3_vnis = bf.q.evpnL3VniProperties().answer().frame()

#     bgp_proc = bf.q.bgpProcessConfiguration().answer().frame()[
#         ['Node', 'VRF', 'Router_ID']]
#     bgp_proc = bgp_proc[bgp_proc.VRF == 'default']

#     df = pd.DataFrame()
#     index = 0
#     for _, proc in bgp_proc.iterrows():
#         rds = l3_vnis[(l3_vnis.Node == proc.Node)]
#         for i, vni in rds.iterrows():
#             actual_rd = rds['Route_Distinguisher'][i]
#             expected_rd = f"{proc.Router_ID}:{vni.VNI}"
#             if actual_rd != expected_rd:

#                 df.loc[index] = rds.loc[i]
#                 index += 1

#     write_to_csv_output(l3_vnis, "L3VNIs")
#     write_to_csv_output(df, "MisconfiguredL3VNI")

#     try:
#         assert df.empty == True
#         record_results(bf, status=STATUS_PASS,
#                        message='All L3 VNIs have properly configured route-distinguisher')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='Found L3 VNIs with incorrect route-distinguisher:\n{}'.format(df))
#         raise e    

# def test_vtep_reachability(bf):
#     """Check that all VTEPs can reach each other."""
#     os.environ['bf_policy_name'] = "VTEP Reachability Policies"
#     bf.asserts.current_assertion = 'Assert all VTEP reachability'

#     # Collect the list of VTEP_IP from vxlanVniProperties and then loop
#     # through to do traceroute
#     l2_vnis = bf.q.vxlanVniProperties().answer().frame()
#     vtep_ip_list = set(l2_vnis['Local_VTEP_IP'])
#     vni_dict = defaultdict(dict)

#     for index, row in l2_vnis.iterrows():
#         node = row['Node']
#         t_ip = row['Local_VTEP_IP']
#         vni_dict[node]['Local_IP'] = t_ip
#         for vtep_ip in vtep_ip_list:
#             if vtep_ip != t_ip:
#                 try:
#                     vni_dict[node]['Remote_IPs'].add(vtep_ip)
#                 except KeyError:
#                     vni_dict[node]['Remote_IPs'] = {vtep_ip}

#     tr_dict = defaultdict(list)
#     failed_count = 0

#     for src_location in vni_dict.keys():
#         for remote_vtep in vni_dict[src_location]['Remote_IPs']:
#             src_ip = vni_dict[src_location]['Local_IP']
#             headers = HeaderConstraints(
#                 srcIps=src_ip, dstIps=remote_vtep,
#                 ipProtocols='udp', dstPorts='4789')
#             tr = bf.q.traceroute(startLocation=src_location + "[@vrf(default)]",
#                                  headers=headers).answer().frame()
#             for trace in tr.Traces[0]:
#                 if trace.disposition != 'ACCEPTED':
#                     failed_count += 1
#                     tr_dict[f"{src_location}:{src_ip}"].append(remote_vtep)
#                     if failed_count > 10:
#                         break

#     #for conversion to csv output
#     df = pd.DataFrame.from_dict(tr_dict,orient='index')
#     write_to_csv_output(df, "VTEPReachabilityIssues")

#     try:
#         assert len(tr_dict) == 0
#         record_results(bf, status=STATUS_PASS,
#                        message='Full VTEP to VTEP reachability')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='Some VTEPs unable to reach others:\n{}'.format(dict(tr_dict)))
#         raise e


# def test_evpn_bgp_sessions_correct(bf):
#     os.environ['bf_policy_name'] = "VXLAN and EVPN Policies"
#     bf.asserts.current_assertion = 'Assert all EVPN BGP sessions are properly configured'
#     bgpComp = bf.q.bgpSessionCompatibility().answer().frame()
#     df = bgpComp[(bgpComp['Address_Families'].apply(lambda x: 'EVPN' in x)) & (
#         bgpComp['Configured_Status'] != 'UNIQUE_MATCH')]
#     write_to_csv_output(bgpComp, "BgpSessions")

#     try:
#         assert len(df) == 0
#         record_results(bf, status=STATUS_PASS,
#                        message='No EVPN BGP sessions are misconfigured')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='EVPN BGP sessions are misconfigured:\n{}'.format(df))
#         raise e

# def test_evpn_bgp_sessions_up(bf):
#     os.environ['bf_policy_name'] = "VXLAN and EVPN Policies"
#     bf.asserts.current_assertion = 'Assert all EVPN BGP sessions are established'
#     bgpSess = bf.q.bgpSessionStatus().answer().frame()
#     df = bgpSess[(bgpSess['Address_Families'].apply(lambda x: 'EVPN' in x)) & (
#         bgpSess['Established_Status'] != 'ESTABLISHED')]
#     write_to_csv_output(bgpSess, "EvpnBgpSessions")

#     try:
#         assert len(df) == 0
#         record_results(bf, status=STATUS_PASS,
#                        message='All EVPN BGP sessions are established')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='EVPN BGP sessions are not established:\n{}'.format(df))
#         raise e

# def test_evpn_l3vni_rd_unique(bf):
#     os.environ['bf_policy_name'] = "VXLAN and EVPN Policies"
#     bf.asserts.current_assertion = 'Assert all L3 VNIs have unique RD'

#     l3vni = bf.q.evpnL3VniProperties().answer().frame()
#     df = l3vni[l3vni.duplicated('Route_Distinguisher', keep=False)].sort_values(
#         'Route_Distinguisher')

#     try:
#         assert len(df) == 0
#         record_results(bf, status=STATUS_PASS,
#                        message='All L3 VNIs have unique RD')
#     except Exception as e:
#         record_results(bf, status=STATUS_FAIL,
#                        message='L3 VNIs with the same RD:\n{}'.format(df))
#         raise e
