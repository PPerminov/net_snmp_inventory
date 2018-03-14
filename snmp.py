#!/usr/bin/env python3

from subprocess import Popen, PIPE
from netaddr import IPNetwork, cidr_merge, cidr_exclude
from urllib import request
from sys import exit
from socket import socket
from easysnmp import snmp_get
from ping3 import ping
from multiprocessing import Pool as pool
from multiprocessing import Manager
from sqlite3 import Connection as connect
try:
    from data import networks
except ImportError:
    message = """Please rename 'data.py_template' to 'data.py' and
               add your networks in networks variable"""
    print(message)
    exit(2)


mp_array = Manager().list()


def db(db_file):
    sql = connect(db_file)
    cursor = sql.cursor()
    commands = [
        """CREATE TABLE if not exists vendors
           (id integer not null primary key autoincrement,
           l_name varchar(150) not null unique);""",
        """CREATE TABLE IF NOT EXISTS routers
           (id integer not null primary key autoincrement,
           value varchar(16) not null unique)""",
        """CREATE TABLE if not exists mac_vendor
           (id integer not null primary key autoincrement,
           mac varchar(20) not null unique,
           vendor integer,
           FOREIGN KEY (vendor) REFERENCES vendors(id)
           ON UPDATE CASCADE ON DELETE RESTRICT);""",
        """CREATE TABLE if not exists ip
           (id integer not null primary key autoincrement,
           ip varchar(16) not null unique);""",
        """CREATE TABLE if not exists mac
           (id integer not null primary key autoincrement,
           mac varchar(20) not null unique);""",
        """CREATE TABLE if not exists devices_main
           (id integer not null primary key autoincrement,
           timestamp datetime not null default current_timestamp,
           mac integer not null,
           ip integer not null,
           FOREIGN KEY (mac) REFERENCES mac(id)
           ON UPDATE CASCADE ON DELETE RESTRICT,
           FOREIGN KEY (ip) REFERENCES ip(id)
           ON UPDATE CASCADE ON DELETE RESTRICT);""",
        """CREATE INDEX if not exists mac_i on devices_main (mac);""",
        """CREATE INDEX if not exists l_n_i on vendors (l_name);"""
    ]
    for command in commands:
        cursor.execute(command)
    cursor.close()
    return sql


def mac_db(sql, file_to_read=None):
    def denuller(line):
        """
        this is for removing unneeded zeroes from the end of mac
        """
        line = line.split('/')
        mac = bin(int(line[0], 16))[2:]
        index = int(line[1])
        return hex(int(mac[:index + 1], 2))[2:]

    def extractor(line):
        line = line.strip().split("\t")
        mac = ''.join(line[0].lower().split(":"))
        if '/' in mac:
            mac = denuller(mac)
        S_name = line[1].lower()
        try:
            L_name = line[2].lower()
        except IndexError:
            L_name = S_name
        return [mac, L_name]

    def filtrer(point):
        if '#' not in point and 'IeeeRegi' not in point:
            return point
        return None

    if file_to_read:
        with open(file_to_read, 'r') as r:
            response = r.read()
    else:
        url = "https://code.wireshark.org/review/"
        url += "gitweb?p=wireshark.git;a=blob_plain;f=manuf"
        response = request.urlopen(url).read().decode()
    response = response.split("\n")
    response = list(filter(filtrer, response))
    response = list(map(extractor, response))
    cursor = sql.cursor()
    vendors = []
    for line in response:
        vendors.append([line[1]])
    cursor.executemany(
        'insert or ignore into vendors (l_name) values(?)', vendors)
    cursor.executemany(
        """insert or ignore into mac_vendor (mac, vendor)
           values(?,(select id from vendors where l_name = ?))""", response)
    sql.commit()
    cursor.close()


def mac_ip(address):
    global mp_array
    mibs = ['1.3.6.1.2.1.3.1.1.2', '1.3.6.1.2.1.4.22.1.2']
    for mib in mibs:
        # because simplier thant pysnmp.
        # Easy snmp have some troubles with HEX values
        cur = Popen(['snmpwalk', '-v1', '-cpublic', address, mib],
                    stdin=PIPE, stdout=PIPE, stderr=PIPE)
        output, err = cur.communicate()
        mac_list = output.decode().lower().strip().split("\n")
        if mac_list != ['']:
            break
    for item in mac_list:
        if 'hex-string' not in item:
            continue
        try:
            tmp_1 = item.split(" = ")
            ip = (tmp_1[0].split(".")[-1:-5:-1])
            ip.reverse()
            ip = '.'.join(ip)
            mac = tmp_1[1].strip().split(" ")
            del(mac[0])
            mac = ''.join(mac)
            mp_array.append((mac, ip))
        except Exception:
            continue


def networker(routers):
    workers = pool(6)
    workers.map(mac_ip, map(lambda x: x[0], routers))
    workers.close()


def net_parse(networks):
    routers = list()
    dbg_list = list()
    name_list = list()
    for item in networks:
        IP_object = IPNetwork(item)
        NET_list = list(IP_object.subnet(24))
        for subnet in NET_list:
            router = str(subnet[1])
            if not ping(router, 0.1):
                continue
            try:
                oid = '1.3.6.1.2.1.1.5.0'
                name = snmp_get(oid, hostname=router,
                                community='public', version=1)
                dbg_list.append(name.value)
                if name.value not in name_list:
                    name_list.append(name.value)
                    routers.append([router])
            except Exception:
                continue
    return routers


def start(sql, update_routers=False):
    cursor = sql.cursor()
    cursor.execute("select value from routers")
    routers = cursor.fetchall()
    if routers == [] or update_routers != False:
        routers = net_parse(networks)
        cursor.executemany(
            "insert or ignore into routers (value) values (?)", routers)
        sql.commit()
        if update_routers == 'Only':
            exit(0)
    networker(routers)
    ip = []
    mac = []
    for line in mp_array:
        ip.append((line[1],))
        mac.append((line[0],))
    cursor.executemany("insert or ignore into ip (ip) values (?)", ip)
    cursor.executemany("insert or ignore into mac (mac) values (?)", mac)
    cursor.executemany(
        """insert or ignore into devices_main (mac, ip)
           values (
                    (select id from mac where mac = ?),
                    (select id from ip where ip = ?)
                  )""", mp_array)
    cursor.close()
    sql.commit()
