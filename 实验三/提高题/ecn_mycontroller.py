#!/usr/bin/env python3
import argparse
import grpc
import os
import sys
from time import sleep

# Import P4Runtime lib from parent utils dir
# Probably there's a better way of doing this.
sys.path.append(
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 '../../utils/'))
import p4runtime_lib.bmv2
from p4runtime_lib.error_utils import printGrpcError
from p4runtime_lib.switch import ShutdownAllSwitchConnections
import p4runtime_lib.helper


def writeForwardRules(p4info_helper, ingress_sw, egress_sw,
                     dst_eth_addr, dst_ip_addr, dst_port):
    table_entry = p4info_helper.buildTableEntry(
        table_name="MyIngress.ipv4_lpm",
        match_fields={
            "hdr.ipv4.dstAddr": dst_ip_addr
        },
        action_name="MyIngress.ipv4_forward",
        action_params={
            "dstAddr": dst_eth_addr,
            "port": dst_port
        })
    egress_sw.WriteTableEntry(table_entry)
    print("Installed Forward rule on %s" % egress_sw.name)


def main(p4info_file_path, bmv2_file_path):
    # Instantiate a P4Runtime helper from the p4info file
    p4info_helper = p4runtime_lib.helper.P4InfoHelper(p4info_file_path)  #初始化p4info_helper对象，用于接下来的解析

    try:
        # Create a switch connection object for s1 and s2;
        # this is backed by a P4Runtime gRPC connection.
        # Also, dump all P4Runtime messages sent to switch to given txt files.
        s1 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s1',
            address='127.0.0.1:50051',
            device_id=0,
            proto_dump_file='logs/s1-p4runtime-requests.txt')
        s2 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s2',
            address='127.0.0.1:50052',
            device_id=1,
            proto_dump_file='logs/s2-p4runtime-requests.txt')
        s3 = p4runtime_lib.bmv2.Bmv2SwitchConnection(
            name='s3',
            address='127.0.0.1:50053',
            device_id=2,
            proto_dump_file='logs/s3-p4runtime-requests.txt')

        # Send master arbitration update message to establish this controller as
        # master (required by P4Runtime before performing any other write operation)
        s1.MasterArbitrationUpdate()
        s2.MasterArbitrationUpdate()
        s3.MasterArbitrationUpdate()

        # Install the P4 program on the switches
        s1.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s1")
        s2.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s2")
        s3.SetForwardingPipelineConfig(p4info=p4info_helper.p4info,bmv2_json_file_path=bmv2_file_path)
        print("Installed P4 Program using SetForwardingPipelineConfig on s3")

        #s1
        writeForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,dst_eth_addr="08:00:00:00:01:01", dst_ip_addr=["10.0.1.1", 32], dst_port=2)
        writeForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,dst_eth_addr="08:00:00:00:01:11", dst_ip_addr=["10.0.1.11", 32], dst_port=1)
        writeForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.2.0", 24], dst_port=3)
        writeForwardRules(p4info_helper, ingress_sw=s1, egress_sw=s1,dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=["10.0.3.0", 24], dst_port=4)

        #s2
        writeForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,dst_eth_addr="08:00:00:00:02:02", dst_ip_addr=["10.0.2.2", 32], dst_port=2)
        writeForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,dst_eth_addr="08:00:00:00:02:22", dst_ip_addr=["10.0.2.22", 32], dst_port=1)
        writeForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.1.0", 24], dst_port=3)
        writeForwardRules(p4info_helper, ingress_sw=s2, egress_sw=s2,dst_eth_addr="08:00:00:00:03:00", dst_ip_addr=["10.0.3.0", 24], dst_port=4)


        #s3
        writeForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s3,dst_eth_addr="08:00:00:00:03:03", dst_ip_addr=["10.0.3.3", 32], dst_port=1)
        writeForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s3,dst_eth_addr="08:00:00:00:01:00", dst_ip_addr=["10.0.1.0", 24], dst_port=2)
        writeForwardRules(p4info_helper, ingress_sw=s3, egress_sw=s3,dst_eth_addr="08:00:00:00:02:00", dst_ip_addr=["10.0.2.0", 24], dst_port=3)



    except KeyboardInterrupt:
        print(" Shutting down.")
    except grpc.RpcError as e:
        printGrpcError(e)

    ShutdownAllSwitchConnections()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='P4Runtime Controller')
    parser.add_argument('--p4info', help='p4info proto in text format from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.p4.p4info.txt')
    parser.add_argument('--bmv2-json', help='BMv2 JSON file from p4c',
                        type=str, action="store", required=False,
                        default='./build/ecn.json')
    args = parser.parse_args()

    if not os.path.exists(args.p4info):
        parser.print_help()
        print("\np4info file not found: %s\nHave you run 'make'?" % args.p4info)
        parser.exit(1)
    if not os.path.exists(args.bmv2_json):
        parser.print_help()
        print("\nBMv2 JSON file not found: %s\nHave you run 'make'?" % args.bmv2_json)
        parser.exit(1)
    main(args.p4info, args.bmv2_json)
