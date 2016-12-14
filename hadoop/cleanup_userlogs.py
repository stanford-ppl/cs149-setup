#!/usr/bin/env python

# Use this script when someone accidentally spews to stdout and kills
# the cluster because HDFS has run out of disk space.

import collections, json, subprocess, sys

def cleanup_userlogs(cluster_name):
    with open('config/state.json', 'rb') as f:
        state = json.load(f, object_pairs_hook=collections.OrderedDict)

    assert cluster_name in state['clusters']
    cluster = state['clusters'][cluster_name]
    for node_name in cluster['nodes']:
        node = state['nodes'][node_name]
        hostname = node['public_dns_name']
        subprocess.check_call(
            ['ssh',
             '-i', 'cs149.pem',
             'ubuntu@%s' % node['public_dns_name'],
             'sudo bash -c "test -d /tmp/mapred/local/userlogs && du -sh /tmp/mapred/local/userlogs && rm -rf /tmp/mapred/local/userlogs/* || true"'])

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print './cleanup_userlogs.py <cluster_name>'
        sys.exit(1)
    cleanup_userlogs(sys.argv[1])
