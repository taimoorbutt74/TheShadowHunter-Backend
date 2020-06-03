# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

# !flask/bin/python
from flask import Flask, jsonify, request
from flask_cors import CORS, cross_origin
import pexpect
import yaml
import uuid
import ast
import sys
import os
import re
import socket
import pymongo
import json
from randmac import RandMac

add_department_scripts = ["openvpn.yml", "makeONETdirectory.yml", "transfer.yml", "vpn.yml", "onetinterface.yml",
                          "onet.yml", "dnet1.yml", "tunnel.yml", "onet_ofctl.yml", "wirelessInterface.yml",
                          "vxlanInterface.yml", "onetMAC.yml"]
script_inventory = "/home/kawish/vagrant_multi_edureka/"
output = []
counter = 0
DNET_IP = "192.168.10.7"
interface_name = []

app = Flask(__name__)
CORS(app, support_credentials=True)


@cross_origin(supports_credentials=True)
# @app.route('/todo/api/v1.0/tasks', methods=['GET'])
# def get_tasks():
#     return jsonify({'tasks': tasks})

@app.route('/add-department', methods=['POST'])
def add_department():
    database_list = {}
    global counter
    interface_name.clear()
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    database_list["account"] = username
    database_list["onet_dep_ip"] = ipaddress
    print(ipaddress)
    print(username)
    print(password)
    with open("/etc/ansible/hosts", "a+", encoding="utf-8") as myfile:
        myfile.write(
            username + " " + "ansible_host=" + ipaddress + " ansible_port=22 " + "ansible_user=" + username + " ansible_password=" + password + " ansible_sudo_pass=" + password + "\n")

    for item in add_department_scripts:
        if (item == "dnet1.yml"):
            ansible_script = read_file(script_inventory + item)
            for tags in ansible_script:
                if tags["tasks"][0]["command"] == "ovs-vsctl add-br br47":
                    tags["tasks"][0]["command"] = "ovs-vsctl add-br br" + str(counter)
                if tags["tasks"][2][
                    "command"] == "ovs-vsctl add-port br47 vxlan0":
                    tags["tasks"][2][
                        "command"] = "ovs-vsctl add-port br" + str(counter) + " vxlan" + str(
                        counter) + " -- set interface vxlan" + str(
                        counter) + " type=vxlan option=remote_ip=10.8.0." + str(counter + 2)
                if tags["tasks"][4]["command"] == "ip tuntap add mode tap tap0":
                    tags["tasks"][4]["command"] = "ip tuntap add mode tap tap" + str(counter)
                    database_list["dnet_tap_interface"] = "tap" + str(counter)
                if tags["tasks"][6]["command"] == "ifconfig tap0 up":
                    tags["tasks"][6]["command"] = "ifconfig tap" + str(counter) + " up"
                if tags["tasks"][8]["command"] == "ovs-vsctl add-port br47 tap0":
                    tags["tasks"][8]["command"] = "ovs-vsctl add-port br" + str(counter) + " tap" + str(counter)
            new_script_path = write_file(script_inventory + item, ansible_script)
            execute_ansible_script(new_script_path, item)
            delete_file(new_script_path)
            dnet_br0 = execute_interface_script(script_inventory + "dnet_ofctl.yml", "dnet_ofctl.yml")
            database_list["dnet_bridge"] = dnet_br0
            counter = counter + 1
        else:
            ansible_script = read_file(script_inventory + item)
            edited_script = scripts_necessary_changes_dept(ansible_script, item, username)
            new_script_path = write_file(script_inventory + item, edited_script)
            if item == "onetinterface.yml":
                interface = execute_interface_script(new_script_path, item)
                interface_name.append(interface)
            elif item == "onet_ofctl.yml":
                dpid = execute_interface_script(new_script_path, item)
                database_list["onet_dpid"] = dpid
            elif item == "vxlanInterface.yml":
                vxlan_interface = execute_interface_script(new_script_path, item)
                database_list["onet_vxlan_port_num"] = vxlan_interface
            elif item == "wirelessInterface.yml":
                wireless_interface = execute_interface_script(new_script_path, item)
                database_list["onet_wireless_port_num"] = wireless_interface
            elif item == "onetMAC.yml":
                onet_mac = execute_interface_script(new_script_path, item)
                database_list["onet_mac"] = onet_mac
            else:
                execute_ansible_script(new_script_path, item)
            delete_file(new_script_path)
    accessing_database("developments", database_list)
    database_list.clear()
    if "openvpn.yml" in add_department_scripts:
        index = add_department_scripts.index("openvpn.yml")
        add_department_scripts[index] = "openvpn2.yml"
    else:
        print("openvpn is already removed")
    return jsonify(True)


def scripts_necessary_changes_dept(script_path, item, username):
    if item == "onetinterface.yml" or item == "tunnel.yml" or item == "vxlanInterface.yml" or item == "onet_ofctl.yml" or item == "onetMAC.yml":
        script_path[0]["hosts"] = username
        return script_path
    elif item == "vpn.yml":
        if counter == 0:
            script_path[0]["vars"]["vpn_name"] = "client"
        else:
            script_path[0]["vars"]["vpn_name"] = "client" + str(counter)
        script_path[0]["hosts"] = username
        script_path[0]["vars"]["username"] = username
        return script_path
    elif item == "onet.yml":
        script_path[0]["vars"]["interface"] = interface_name[0]
        script_path[0]["hosts"] = username
        return script_path
    elif item == "transfer.yml":
        if counter == 0:
            script_path[0]["vars"]["vpn_name"] = "client"
            script_path[1]["vars"]["vpn_name"] = "client"
            script_path[1]["vars"]["username"] = username
        else:
            script_path[0]["vars"]["vpn_name"] = "client" + str(counter)
            script_path[1]["vars"]["vpn_name"] = "client" + str(counter)
            script_path[1]["vars"]["username"] = username
        script_path[1]["hosts"] = username
        return script_path
    elif item == "openvpn.yml":
        script_path[0]["vars"]["IP"] = DNET_IP
        return script_path
    elif item == "wirelessInterface.yml":
        script_path[0]["vars"]["Interface"] = interface_name[0]
        script_path[0]["hosts"] = username
        return script_path
    elif item == "makeONETdirectory.yml":
        script_path[0]["vars"]["username"] = username
        script_path[0]["hosts"] = username
        return script_path
    elif item == "openvpn2.yml":
        script_path[0]["vars"]["clientname"] = "client" + str(counter)
        return script_path


def execute_interface_script(script, item):
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8', timeout=60)
    result = child.read()
    if item == "onetinterface.yml":
        return re.search('(\B"msg":\W*")(\w*).*?\s', result).group(2)
    elif item == "onet_ofctl.yml" or item == "dnet_ofctl.yml":
        return re.search('dpid:?(\w*)', result).group(1)
    elif item == "vxlanInterface.yml" or item == "wirelessInterface.yml":
        return re.search('"msg":\W*(\d*)', result).group(1)
    elif item == "onetMAC.yml":
        return re.search('LOCAL(.*)(\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)', result).group(2)


def execute_ansible_script(script, item):
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8', timeout=60)
    # child.expect(timeout=60)
    result = child.interact()
    child.close()
    # ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    # out = ansi_escape.sub('', out)
    # print(out)
    # output.append(out)


def delete_file(file_path):
    if os.path.exists(file_path):
        os.remove(file_path)
    else:
        print("The file does not exist")


def read_file(file_path):
    yml = yaml
    with open(file_path) as yml_file:
        return yml.load(yml_file)


def write_file(file_path, script):
    yml = yaml
    output_file_path = file_path + str(uuid.uuid1()) + ".yml"
    with open(output_file_path, 'w+') as yml_file:
        yml.dump(script, yml_file)
    return output_file_path


@app.route('/getjson', methods=['POST'])
def get_json():
    print(request.json)
    return jsonify("recieved")

    # @app.route('/execute-ansible', methods=['GET'])
    # def ansible():
    #     child = pexpect.spawn("ansible-playbook test.yml", encoding='utf-8')
    #     #child.logfile_read =sys.stdout
    #     #child.logfile = open('xyz.txt', 'w')
    #     #child.expect(pexpect.EOF)
    #     #child.interact()
    #     #print(child.logfile_read)
    # child.expect('"out": {.*"stderr_lines":')
    #     #child.expect(pexpect.EOF)
    # ab = (child.after).replace('"out": {', '')
    # print(ab)
    #     return (ab) #({'result': str(ab)})
    #     #print(cson.dumpshild.read())
    #     #return jsonify({'result': f''+str((child.read()))})

    # with open('data.txt', 'w') as outfile:
    # json.dump(data, outfile)
    # with open("data_file.json", "r") as read_file:
    # data = json.load(read_file)
    # child.logfile_read = sys.stdout
    # child. logfile = open('xyz.txt', 'w')

    # print(child.readlines())
    # a=bytes(child.read().encode('UTF-8'))
    # a= a.decode(encoding='UTF-8', errors='ignore')
    # a= json.dumps(a,ensure_ascii=False)
    # a=a.encode('ascii','ignore')
    # a=ast.literal_eval(a)
    # print(a.decode('latin-1')) #unicode_escape
    # with open('xyz.txt', 'w') as outfile:
    #     outfile.write(a)
    # b= json.dumps(a,ensure_ascii=False, indent=0).encode('utf8')

    # print(b.decode('utf8'))
    # child.expect(pexpect.EOF)
    # child.interact()
    '''
    child.expect('"out": {.*"stderr_lines":', timeout=60)
    ab = (child.after).replace('"out": {', ''
    '''
    # print(child.read())
    # print(json.dump(child.re


def execute_VM_scripts(script, item):
    print(item)
    child = pexpect.spawn("ansible-playbook " + script, encoding='utf-8',
                          timeout=60)
    # child.expect(timeout=60)
    # child.interact()
    output = child.read()
    child.close()
    if item == "onetssh.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    elif item == "onethttp.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    elif item == "onetmysql.yml":
        interface = re.search('("msg": ")(.*)(")', output).group(2)
        return interface
    ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    output = ansi_escape.sub('', output)
    print(output)
    return output


def scripts_necessary_changes_VM_onet(script, item, username):
    script[0]["vars"]["username"] = username
    script[0]["hosts"] = username
    return script


def scripts_necessary_changes_VM_dnet(script, item, ipaddress, interface , mac_address):
    script[0]["vars"]["interface"] = interface
    script[0]["vars"]["IPaddress"] = ipaddress
    script[0]["vars"]["macAddress"] = mac_address
    return script

def get_tap_interface_name(query):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    mycol = mydb["developments"]
    for x in mycol.find(query):
        interface = x["dnet_tap_interface"]
        myclient.close()
        return interface
    myclient.close()


@app.route('/execute-VM', methods=['POST'])
def ansible1():
    output_array = []
    database_list = {}
    req = request.json
    # req = request.values.values()
    service_name = req["User_data"]["service"]
    username = req["User_data"]["account"]
    database_list["account"] = username
    database_list["service"] = service_name
    query = {"account": username}
    if service_name == "SSH":
        item_onet = "onetssh.yml"
        item_dnet = "dnetssh.yml"
    elif service_name == "HTTP":
        item_onet = "onethttp.yml"
        item_dnet = "dnethttp.yml"
    elif service_name == "MYSQL":
        item_onet = "onetmysql.yml"
        item_dnet = "dnetmysql.yml"
    else:
        return
    ansible_script = read_file(script_inventory + item_onet)
    edited_script = scripts_necessary_changes_VM_onet(ansible_script, item_onet, username)
    new_script_path = write_file(script_inventory + item_onet, edited_script)
    ipaddress = execute_VM_scripts(new_script_path, item_onet)
    database_list["onet_VM_ip"] = ipaddress
    delete_file(new_script_path)
    tuntap =  "tap0" #get_tap_interface_name(query)
    MAC = RandMac("080027000000")
    database_list["dnet_VM_mac"] = MAC.mac
    ansible_script = read_file(script_inventory + item_dnet)
    edited_script = scripts_necessary_changes_VM_dnet(ansible_script, item_dnet, ipaddress, tuntap , MAC.mac)
    new_script_path = write_file(script_inventory + item_dnet, edited_script)
    VM_result = execute_VM_scripts(new_script_path, item_dnet)
    delete_file(new_script_path)
    accessing_database("VMdetails" , database_list)
    database_list.clear()
    output_array.append(VM_result)
    return jsonify(output_array)
# child = pexpect.spawn("ansible-playbook /home/kawish/vagrant_multi_edureka/dnethttp.yml", encoding='utf-8', timeout=60)
# a = child.read()
# child.close()
# #child.expect(timeout=60)
# ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
# a = ansi_escape.sub('',a)
# print(a)
# return (jsonify(a))

@app.route('/Delete-VM', methods=['POST'])
def ansible3():
    output_array = []
    req = request.json
    service = req["User_data"]["service"]
    if service == "SSH":
        child = pexpect.spawn("ansible-playbook /home/kawish/vagrant_multi_edureka/sshhalt.yml", encoding='utf-8',
                              timeout=60)
        # child.expect(timeout=60)
        child.interact()
        output = child.read()
        child.close()
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        output = ansi_escape.sub('', output)
        print(output)
        output_array.append(output)
    if service == "HTTP":
        child = pexpect.spawn("ansible-playbook /home/kawish/vagrant_multi_edureka/httphalt.yml", encoding='utf-8',
                              timeout=60)
        # child.expect(timeout=60)
        child.interact()
        output = child.read()
        child.close()
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        output = ansi_escape.sub('', output)
        print(output)
        output_array.append(output)

    elif service == "MySQL":
        child = pexpect.spawn("ansible-playbook /home/kawish/vagrant_multi_edureka/mysqlhalt.yml", encoding='utf-8',
                              timeout=60)
        # child.expect(timeout=60)
        child.interact()
        output = child.read()
        child.close()
        ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
        output = ansi_escape.sub('', output)
        print(output)
        output_array.append(output)

@app.route('/execute-ansible', methods=['POST'])
def ansible2():
    req = request.json
    print(req)
    ipaddress = req["User_data"]["IPaddress"]
    username = req["User_data"]["account"]
    password = req["User_data"]["password"]
    print(ipaddress)
    print(username)
    print(password)
    with open("/etc/ansible/hosts", "a+", encoding="utf-8") as myfile:
        myfile.write(
            username + " " + "ansible_host=" + ipaddress + " ansible_port=22 " + "ansible_user=" + username + " ansible_password=" + password + " ansible_sudo_pass=" + password + "\n")

    # output_array = []
    # scripts = ["openvpn.yml","transfer.yml", "vpn.yml", "onet.yml","dnet1.yml", "tunnel.yml"]
    # for item in scripts:
    #     print((item))
    #     child = pexpect.spawn("ansible-playbook /home/kawish/vagrant_multi_edureka/"+item, encoding='utf-8', timeout=60)
    #     # child.expect(timeout=60)
    #     child.interact()
    #     output = child.read()
    #     child.close()
    #     ansi_escape = re.compile(r'\x1B[@-_][0-?]*[ -/]*[@-~]')
    #     output = ansi_escape.sub('',output)
    #     print(output)
    #     output_array.append(output)
    # return (jsonify(output_array))


@app.route('/execute-scanner', methods=['POST'])
def scanner():
    req1 = request.json
    req = request.values.values()
    ipaddress = req1["User_data"]["IPaddress"]
    # print(dict_req["User_data"])
    print("In the scanner method")
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('192.168.1.101', 8090))
    client.sendall(ipaddress.encode())
    client.close()
    return jsonify("IP address recieved")

    # child.expect('"out": {.*"stderr_lines":', timeout=60)
    # ab = (child.after).replace('"out": {', '')
    # print(ab)
    # return ({'result': str(ab)})


def accessing_database(collection_name, mylist):
    myclient = pymongo.MongoClient("mongodb://localhost:27017/")
    mydb = myclient["shadowhunter-backend"]
    if collection_name == "developments":
        mycol = mydb["developments"]
        data = mycol.insert_one(mylist)
        print(data)
    if collection_name == "VMdetails":
        mycol = mydb["VMdetails"]
        data = mycol.insert_one(mylist)
        print(data)
    print(mylist)
    myclient.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)  # debug=True
