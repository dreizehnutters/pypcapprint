# -*- coding: utf-8 -*-
#! /usr/bin/env python3
from time import time
from csv import writer
from functools import wraps
from ast import literal_eval
from argparse import ArgumentParser
from subprocess import check_output as co
from os import path, getcwd, remove, makedirs

# TODOS
    # ignore arp(no ip layer) and icmp == (no trans ports) in tshark
    # snort file statisitcs
    # def order on ip:port for key manegment
    # make tshark/snort parsing parallel
    # make -l parallel
    # check lua config for app_id_dir and packet_trace

PARSER = ArgumentParser(description='pcap fingerprint-analyse tool')
PARSER.add_argument('-f', '--file', default='', help='pcap')
PARSER.add_argument('-s', '--snort', default='/opt/snort3/', nargs='?', help='path to snort3 base dir')
PARSER.add_argument('-c', '--config', default=False, nargs='?', help='path to snort3 config lua')
PARSER.add_argument('-l', '--list', default=None, nargs='?', help='list of pcaps to process')
PARSER.add_argument('-o', '--out', default=None, nargs='?', help='path to output directory')
PARSER.add_argument('--verbose', action='store_true')
PARSER.add_argument('--noP0f', action='store_true')
PARSER.add_argument('--noSnort', action='store_true')
PARSER.usage = "\tpython3 fingerprint.py -f <PATH_TO_PCAP> -s <SNORT_PATH> -c <SNORT_CONFIG.LUA>\n\
\tpython3 fingerprint.py -f ../../some.pcap -s /opt/snort3/ -c snort.lua\n\
\tpython3 fingerprint.py -s /opt/snort3 -c snort.lua -l pcapfiles.list --verbose"
ARGS = PARSER.parse_args()


def measure(func):
    """time decorator"""
    @wraps(func)
    def _time_it(*args, **kwargs):
        start = time()
        try:
            return func(*args, **kwargs)
        finally:
            if ARGS.verbose is True:
                print(f"[*] {func.__name__} took {(time() - start)/60:.2f} minutes{' '*42}")
    return _time_it


def test_file(in_file, should_exit=False):
    """test if in_file exists"""
    if not path.exists(in_file) or path.isdir(in_file):
        if should_exit:
            exit(f"{in_file} does not exits!")
        print(f"{in_file} does not exits!")
        return False
    return True

@measure
def tshark_analysis(filepath):
    """tshark protocol analysis using -Tek option"""
    tshark_dict = dict()
    print(f"[*] tshark analysis")
    tmp_file = 'tmp.dump'
    co([f"tshark -r {filepath} -Tek -e ip.src_host\
                                    -e ip.dst_host\
                                    -e tcp.port\
                                    -e udp.port\
                                    -e frame.protocols\
                                    | sed '1~2d' > {tmp_file}"], shell=True)
    max_ = co([f"cat {tmp_file} | wc -l"], shell=True).strip().decode('ascii')

    with open(f"{tmp_file}", 'r') as file:
        for idx, block in enumerate(file):
            if ARGS.verbose is True:
                print(f"\t[~] parsing packet {idx+1}/{max_}\t\t", end='\r')
            block = literal_eval(block)
            try:
                src = block['layers']['ip_src_host'][0]
                dst = block['layers']['ip_dst_host'][0]
            except KeyError:
                continue

            protos = block['layers']['frame_protocols'][0].split(':')
            try:
                sport, dport = block['layers']['tcp_port']
            except KeyError:
                try:
                    sport, dport = block['layers']['udp_port']
                except KeyError:
                    continue

            flow1 = f"{src}:{sport}<->{dst}:{dport}"
            flow2 = f"{dst}:{dport}<->{src}:{sport}"
            try:
                tshark_dict[flow1]
            except KeyError:
                try:
                    tshark_dict[flow2]
                except KeyError:
                    tshark_dict[flow1] = set(protos)
                else:
                    for proto in protos:
                        tshark_dict[flow2].add(proto)
            else:
                for proto in protos:
                    tshark_dict[flow1].add(proto)

    for k, val in tshark_dict.items():
        tshark_dict[k] = list(val)

    remove(f"{tmp_file}")

    return tshark_dict

@measure
def p0f_analysis(filepath):
    """get p0f signatures for IPs"""
    def helper(block):
        """try to split 'client' / 'server' information from a block"""
        try:
            host = block.split('client')[1].split('\\n')[0].strip()[2:].split('/')[0]
            port = block.split('client')[1].split('\\n')[0].strip()[2:].split('/')[1]\
                            .split('|')[0].strip()
        except IndexError:
            try:
                host = block.split('server')[1].split('\\n')[0].strip()[2:].split('/')[0]
                port = block.split('server')[1].split('\\n')[0].strip()[2:].split('/')[1]\
                                .split('|')[0].strip()
            except IndexError:
                raise f"\t[~] error on {block}"
            else:
                cli_serv = 'server'
        else:
            cli_serv = 'client'

        return host, port, cli_serv

    print(f"[*] p0f analysis")
    p0f = co([f"p0f -r {filepath} | tail -n +9 | head -n -2"], shell=True)\
            .strip().decode('ascii')
    p0f_dict = {}
    blocks = p0f.split('`----')
    for idx, block in enumerate(blocks):
        if ARGS.verbose is True:
            print(f"\t[~] parsing {idx+1}/{len(blocks)} p0f signatures", end='\r')
        if len(block) > 1:
            try:
                host, port, cli_serv = helper(block)
            except Exception as e:
                print(e)
                continue
            if 'os       = ' in block:
                target_os = block.split('os       = ')[1].split('\n')[0]
            elif 'app      = ' in block:
                target_os = block.split('app      = ')[1].split('\n')[0]
            else:
                target_os = 'unkown'
            try:
                p0f_dict[host]
            except KeyError:
                p0f_dict[host] = [set([target_os]), set([cli_serv]), set([port])]
            else:
                for i, set_ in zip((target_os, cli_serv, port), p0f_dict[host]):
                    set_.add(i)

    # remove useless information
    for _, value in p0f_dict.items():
        if len(value[0]) > 1:
            value[0].discard('unkown')
        if len(value[0]) > 1:
            value[0].discard('???')

    return p0f_dict

@measure
def snort_analysis(filepath):
    """get snort output for pcap"""
    log_dir = 'tmp_log'
    if not path.exists(log_dir):
        makedirs(log_dir)
    snort_dict = {}
    print(f"[*] snort analysis")
    if ARGS.verbose is True:
        print(f"\t[~] using {SNORT_CONFIG} for snort configuartion")

    _ = co([f"{ARGS.snort}/bin/snort -c {SNORT_CONFIG}\
                                 -r {filepath}\
                                 -s 65535\
                                 -k none\
                                 -l {log_dir}"], shell=True)\
                            .strip().decode('ascii')

    max_ = int(int(co([f"cat {log_dir}/packet_trace.txt | wc -l"], shell=True)\
                    .strip().decode('ascii'))//7)
    with open(f"{log_dir}/packet_trace.txt", 'r') as packet_trace:
        for idx, block in enumerate(packet_trace.read().split('\n\n')[:-1]):
            if ARGS.verbose is True:
                print(f"\t[~] parsing snort packet traces {idx+1}/{max_}", end='\r')
            if 'AppID' in block and 'client: (0)' not in block:
                infos = block.split('\n')
                try:
                    srcdst = [x.split(' ') for x in\
                                [x.split('->') for x in infos if 'proto' in x][0]]
                    src, dst = srcdst[0][0], srcdst[1][1]
                    transport = [x for x in infos if 'Packet' in x][-1]\
                                    .split(',')[0]\
                                    .split(': ')[-1]\
                                    .split(' ')[0]\
                                    .lower()
                    app = [x for x in infos if 'client:' in x][0]\
                                .split('client: ')[1]\
                                .split('(')[0]
                except IndexError:
                    print(f"error on block: {block}")
                    continue

                flow1 = f"{src}<->{dst}"
                flow2 = f"{dst}<->{src}"
                try:
                    snort_dict[flow1]
                except KeyError:
                    try:
                        snort_dict[flow2]
                    except KeyError:
                        snort_dict[flow1] = set([app, transport])
                    else:
                        snort_dict[flow2].add(app)
                        snort_dict[flow2].add(transport)
                else:
                    snort_dict[flow1].add(app)
                    snort_dict[flow1].add(transport)

    for k, val in snort_dict.items():
        snort_dict[k] = list(val)

    from shutil import rmtree
    rmtree(log_dir)

    return snort_dict


def save_fingerprint(tshark_dict, snort_dict, p0f_dict, working_file):
    """write fingerprint dict to file"""
    if ARGS.out is None:
        prefix = getcwd()
    else:
        prefix = ARGS.out
        if not path.exists(prefix):
            makedirs(prefix)
    if not prefix[-1] == '/':
        prefix += '/'

    file_name = f"{prefix}{working_file.split('/')[-1]}_info.csv"
    print(f"[#] saving {working_file}'s fingerprint to: {file_name}")

    # merge tshark dict with snort dict
    comb_dict = dict()
    if tshark_dict != {}:
        for k, value in tshark_dict.items():
            try:
                apps = snort_dict[k]
            except KeyError:
                try:
                    flow_split = k.split("<->")
                    apps = snort_dict[f"{flow_split[1]}<->{flow_split[0]}"]
                except KeyError:
                    comb_dict[k] = [value, []]
                else:
                    comb_dict[k] = [value, apps]
            else:
                comb_dict[k] = [value, apps]
    else:
        for k, value in snort_dict.items():
            comb_dict[k] = [[], value]

    with open(f"{file_name}", 'w') as csv_file:
        csv_writer = writer(csv_file, delimiter=';')
        if len(p0f_dict.keys()) > 1:
            csv_writer.writerow(['IP', 'OS', 'type', 'ports'])
            for info in p0f_dict:
                line = []
                for set_ in p0f_dict[info]:
                    line += ["/".join([x for x in list(set_)])]
                csv_writer.writerow([info] + line)
            csv_writer.writerow([])
        if len(comb_dict.keys()) > 1:
            csv_writer.writerow(['IPx', 'IPy', 'protocols', 'apps'])
            for line in comb_dict:
                tmp = []
                for list_ in comb_dict[line]:
                    tmp += ["/".join([x for x in list(list_)])]
                csv_writer.writerow([x for x in line.split('<->')] + tmp)

@measure
def make_fingerprint(working_file, progress=(1, 1)):
    """get fingerprints from file and save to csv"""
    if test_file(working_file):
        print(f"[#] working on {working_file} ({progress[0]}/{progress[1]})")

        tshark_dict = tshark_analysis(working_file)
        snort_dict = snort_analysis(working_file) if not ARGS.noSnort else {}
        p0f_dict = p0f_analysis(working_file) if not ARGS.noP0f else {}

        save_fingerprint(tshark_dict, snort_dict, p0f_dict, working_file)


if __name__ == '__main__':
    SNORT_CONFIG = f"{ARGS.snort}etc/snort/snort.lua" if not ARGS.config else ARGS.config
    test_file(SNORT_CONFIG, True)
    if ARGS.list:
        test_file(ARGS.list, True)
        with open(ARGS.list, 'r') as files:
            LINES = files.readlines()
            MAX_FILES = len(LINES)
            for idx, file in enumerate(LINES):
                make_fingerprint(file.strip(), (idx+1, MAX_FILES))
    else:
        if not ARGS.file == '':
            make_fingerprint(ARGS.file)
        else:
            exit("no file to work with")
