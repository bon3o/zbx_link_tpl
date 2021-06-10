#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import requests
import json
import argparse
import configparser
import os
import itertools
import logging
import platform
import time
import copy

if 'LINUX' in platform.platform().upper():
    logFile = '/tmp/link_templates.log'
else:
    logFile = 'link_templates.log'

progressFile = 'link_template_progress.json'
logger = logging.getLogger('link_templates')
logger.setLevel(logging.DEBUG)
fh = logging.FileHandler(logFile)
fh.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s-%(levelname)s:%(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)
logger.info('Starting check for templates in Zabbix.')
config_file = (os.path.abspath(__file__)[:-2] + 'conf')
errors = []
testZabbixGroups = []
testZabbixGroupsIds = []
prodZabbixGroups = []
prodZabbixGroupsIds = []
prodTemplatesDict = {}
ts = int(time.time())
timeDelta = 21600 # Minimum time delta in seconds between "link" and "clear" operations. That should be enought to complete all lld rules.  

if os.path.isfile(progressFile): # If there is an existing config file, it means that the script has already been running before.
    with open(progressFile, 'r') as f:
        currentConfig = f.read()
        try: 
            currentConfig = json.loads(currentConfig)
        except:
            logger.error('File {} has invalid format and could not be read. \
Operation aborted.'.format(progressFile))
            print('Invalid progress file format. See log file {} for errors.\
No changes were made.'.format(logFile))
            exit(0)
else:
    currentConfig = {} # Otherwise it is the first run


class ZabbixAPI(object):

    def __init__(self, user, password):
        self.zheaders = {'Content-Type': 'application/json-rpc'}
        self.zurl = <Zabbix api url>
        self.login = user
        self.password = password
        self.token = self.get_auth_key()

    def get_auth_key(self):
        data = {
            "jsonrpc" : "2.0",
            "method" : "user.login",
            "params" : {
                "user" : self.login,
                "password" : self.password
                },
                "id" : 1
            }

        try:
            r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json()
        except:
            print('Ошибка подключения к Zabbix. Неверный адрес или сетевой сбой.')
            logger.error('Ошибка подключения к Zabbix. Неверный адрес или сетевой сбой.')
            exit(0)
        try:
            auth_key = r['result']
        except:
            print('Ошибка получения токена авторизации(Неправильный пароль в Zabbix?).')
            logger.error('Ошибка получения токена авторизации(Неправильный пароль в Zabbix?).')
            exit(0)
        return auth_key

    def get_hosts(self, groupsIds):
        data = {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                     "groupids" : groupsIds,
                     "output": ["host"],
                     "selectGroups": ["name"],
                     "selectParentTemplates": [
                        "templateid",
                        "name"
                     ]
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r

    def get_hosts_by_name(self, names):
        data = {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": ["host"],
                     "selectGroups": ["name"],
                     "selectParentTemplates": [
                        "templateid",
                        "name"
                     ],
                    "filter": {
                        "host": names
                    }
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r

    def get_hostGroupsIds(self, name):
        data = {
                "jsonrpc": "2.0",
                "method": "hostgroup.get",
                "params": {
                    "output": ["groupid", "name"],
                    "search": {
                        "name" : name
                    }
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r


    def get_templatesIds(self, names):
        if names:
            if isinstance(names, str):
                names = [n.strip() for n in names.split(',')]
        else:
            return []
        data = {
                "jsonrpc": "2.0",
                "method": "template.get",
                "params": {
                    "output": ["hostid", "host"],
                    "filter": {
                        "host": names
                    }
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
    
    def get_items(self, hostId, templateId):
        data = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": ["itemid", "name"],
                    "hostids": hostId,
                    "filter": {
                        "templateid": templateId
                    },
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
    
    def get_items_from_template(self, templateId):
        data = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": ["itemid", "name"],
                    "templateids" : templateId 
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r

    
    def get_lld_from_template(self, templateId): # get all lld rules from template
        data = {
                "jsonrpc": "2.0",
                "method": "discoveryrule.get",
                "params": {
                    "output": ["itemid", "name"],
                    "templateids" : templateId
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r

    def get_items_from_host_by_template(self, hostId, itemId): # Get items that were created on the host by a template
        data = {
                "jsonrpc": "2.0",
                "method": "item.get",
                "params": {
                    "output": ["itemid", "name"],
                    "hostids": hostId,
                    "filter": {
                        "templateid": itemId,
                    }
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
    
    def get_lld_from_host_by_template(self, hostId, itemId):
        data = {
                "jsonrpc": "2.0",
                "method": "discoveryrule.get",
                "params": {
                    "output": ["itemid", "name", "templateid"],
                    "hostids" : hostId,
                    "filter" : {
                        "templateid" : itemId
                    }
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
    
    def get_all_templates_from_host(self, hostId):
        data = {
                "jsonrpc": "2.0",
                "method": "host.get",
                "params": {
                    "output": ["hostid"],
                    "selectParentTemplates": [
                        "templateid",
                        "name"
                    ],
                    "hostids": hostId
                },
                "id": 1,
                "auth": self.token
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r


    def update_templates(self, hostId, templateIds):
        data = {
                "jsonrpc": "2.0",
                "method": "host.update",
                "params": {
                    "hostid": hostId,
                    "templates": templateIds
                },
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
    
    def delete_items(self, itemIds):
        data = {
                "jsonrpc": "2.0",
                "method": "item.delete",
                "params": itemIds,
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
        
    def delete_lld(self, itemIds):
        data = {
                "jsonrpc": "2.0",
                "method": "discoveryrule.delete",
                "params": itemIds,
                "auth": self.token,
                "id": 1
            }
        r = requests.post(self.zurl, headers=self.zheaders, data=json.dumps(data)).json().get('result')
        return r
        

def relink_templates(config, args, zabbix):
    testZabbixHostsFiltered = []
    currentHostCount = 0
    testContourNameList = [c.strip() for c in config['TEST'].get('contourList').split(',')] #Get list of test contours
    prodContourNameList = [c.strip() for c in config['PROD'].get('contourList').split(',')] #Get list of prod contours
    prodTemplates = zabbix.get_templatesIds(config['ZABBIX'].get('templateList')) 
    for template in prodTemplates:
        prodTemplatesDict[template.get('templateid')] = template.get('host')
    tabooTemplatesIds = [t['templateid'] for t in zabbix.get_templatesIds(config['ZABBIX'].get('tabooTemplatesList'))]
    for contour in testContourNameList:
        s = zabbix.get_hostGroupsIds(contour)
        if s:
            testZabbixGroups.extend(s)
    for testZabbixGroup in testZabbixGroups:
        if testZabbixGroup.get('name').endswith(tuple(testContourNameList)) and testZabbixGroup.get('name').startswith('IS'):
            testZabbixGroupsIds.append(testZabbixGroup.get('groupid'))
    for contour in prodContourNameList:
        s = zabbix.get_hostGroupsIds(contour)
        if s:
            prodZabbixGroups.extend(s)
    for prodZabbixGroup in prodZabbixGroups:
        if prodZabbixGroup.get('name').endswith(tuple(prodContourNameList)) and prodZabbixGroup.get('name').startswith('IS'):
            prodZabbixGroupsIds.append(prodZabbixGroup.get('groupid'))
    
    zabbixSearchedHosts = zabbix.get_hosts(testZabbixGroupsIds)
    excludedTestHosts = config['TEST'].get('testServers')
    excludedProdHosts = config['PROD'].get('prodServers')

    if excludedTestHosts:
        excludedTestHosts = [x.strip() for x in excludedTestHosts.split(',')]
        zabbixExcludedHosts = zabbix.get_hosts_by_name(excludedTestHosts)
        testZabbixHostsFiltered += zabbixExcludedHosts

    if excludedProdHosts:
        excludedProdHosts = [x.strip() for x in excludedProdHosts.split(',')]


    for host in zabbixSearchedHosts:
        found = 0
        if host['host'] in excludedProdHosts:
            print('Found excluded prod host \'{}\'. Skipping it.'.format(host['host']))
            continue
        for group in host['groups']:
            if group['groupid'] in prodZabbixGroupsIds:
                found = 1
                break
        for template in host['parentTemplates']:
            if template['templateid'] in tabooTemplatesIds:
                found = 1
                break
        if not found:
            testZabbixHostsFiltered.append(host)
    for host in testZabbixHostsFiltered:
        templateInfo = []
        foundProdTemplates = 0
        templatesOnHost = [x.get('templateid') for x in (zabbix.get_all_templates_from_host(host['hostid']))[0].get('parentTemplates')]
        for template in host['parentTemplates']:
            if template.get('templateid') in prodTemplatesDict:    #.values():
                foundProdTemplates += 1
                testTemplateName = '{} TS'.format(prodTemplatesDict[template.get('templateid')])
                testTemplateId = zabbix.get_templatesIds(testTemplateName)
                if not testTemplateId:
                    logger.error('No template with name \'{0}\' was found in Zabbix for host \'{1}\'. \
Skipping host.'.format(testTemplateName, host['host']))
                    break
                logger.info('Host \'{0}\' has a prod version of template \'{1}\'. \
Will unlink it from host and link \'{2}\'.'.format(host['host'], template.get('name'), testTemplateName))
                print('Host \'{0}\' has a prod version of template \'{1}\'. \
Will unlink it from host and link \'{2}\'.'.format(host['host'], template.get('name'), testTemplateName))
                try:
                    itemsFromTemplate = zabbix.get_items_from_template(template.get('templateid'))
                    itemsOnHostFromTemplate = zabbix.get_items_from_host_by_template(host['hostid'], [x['itemid'] for x in itemsFromTemplate])
                    rulesFromTemplate = zabbix.get_lld_from_template(template.get('templateid'))
                    rulesOnHostFromTemplate = zabbix.get_lld_from_host_by_template(host['hostid'], [x['itemid'] for x in rulesFromTemplate])
                    templateInfo.append({'templateId' : template.get('templateid'), 'items' : [x['itemid'] for x in itemsOnHostFromTemplate], 
                        'lld' : [x['itemid'] for x in rulesOnHostFromTemplate], 'templateName' : template.get('name')})
                    templatesOnHost.remove(template.get('templateid'))
                    templatesOnHost.append(testTemplateId[0].get('templateid'))
                except:
                    print('Error getting itemids from template. Zabbix API returned an error. \
Skipping {}'.format(template.get('name')))
                    logger.error('Error getting itemids from template. \
Zabbix API returned an error. Skipping {}'.format(template.get('name')))
                    break
        # ВСЕ ДЕЙСТВИЯ НАД ШАБЛОНАМИ ТОЛЬКО НА ЭТОМ УРОВНЕ!!!!!!
        if foundProdTemplates:
            if not args.debug:
                updated = zabbix.update_templates(host['hostid'], templatesOnHost) #Uncomment before deploying
            else:
                updated = 1 # Comment before deploying
            if updated:
                logger.info('Updated templates on host \'{0}\'. \
New templates id list is \'{1}\'.'.format(host['host'], templatesOnHost))
                print('Updated templates on host \'{0}\'. \
New templates id list is \'{1}\'.'.format(host['host'], templatesOnHost))
                currentHostCount += 1
            else:
                print('Error while updating template list on host \'{}\''.format(host['host']))
                continue
        if templateInfo:
            currentConfig.update({
                host['hostid'] : {
                    'templates' : templateInfo, 
                    'timestamp' :  ts, 
                    'hostname' : host['host']
                    }
                })
        if currentHostCount == int(args.limit):
            logger.info('Limit of hosts per operation exceded. \
Stopping script. Current limit is \'{}\''.format(args.limit))
            print('Limit of hosts per operation exceded. Stopping script.')
            break
    if currentConfig and not args.debug:
        with open(progressFile, 'w') as f:
            f.write(json.dumps(currentConfig))
                
def clear_orphanded(config, args, zabbix):
    currentHostCount = 0
    resultDict = copy.deepcopy(currentConfig)
    for host, info in currentConfig.items():
        itemsToDelete = []
        lldToDelete = []
        if (ts - info.get('timestamp')) <= timeDelta or args.debug:
            print('Time delta between link operation and clear operation on host \
\'{0}\' is less then {1} hours. To early to proceed.'.format(info['hostname'], timeDelta/3600))
            continue
        currentItemsOnHostWithoutTemplate = zabbix.get_items(host, 0)
        currentLldOnHostWithoutTemplate = zabbix.get_lld_from_host_by_template(host, 0)
        if currentItemsOnHostWithoutTemplate:
            for item in currentItemsOnHostWithoutTemplate:
                for template in info.get('templates'):
                    if item.get('itemid') in template.get('items'):
                        itemsToDelete.append(item.get('itemid'))
        if currentLldOnHostWithoutTemplate:
            for lld in currentLldOnHostWithoutTemplate:
                for template in info.get('templates'):
                    if lld.get('itemid') in template.get('lld'):
                        lldToDelete.append(lld.get('itemid'))
        
        if itemsToDelete or lldToDelete:
            currentHostCount += 1
        if itemsToDelete:
            print('Found orphanded items left from old template. \
Will delete next items: {}'.format(itemsToDelete))
            logger.info('Found orphanded items left from old template. \
Will delete items: {}'.format(itemsToDelete))
            if not args.debug:
                zabbix.delete_items(itemsToDelete)
            else:
                print('Delete {}'.format(itemsToDelete))
        if lldToDelete:
            print('Found orphanded lld rules left from old template. \
Will delete rules: {}'.format(lldToDelete))
            logger.info('Found orphanded lld rules left from old template. \
Will delete rules: {}'.format(lldToDelete))
            if not args.debug:
                zabbix.delete_lld(lldToDelete)
            else:
                print('Delete {}'.format(lldToDelete))
        resultDict.pop(host)
        if not args.debug:
            with open(progressFile, 'w') as f:
                f.write(json.dumps(resultDict))
        if currentHostCount == int(args.limit):
            print('Limit of host per operation exceded. Stopping script. \
Hosts left for operation: {}'.format(len(resultDict)))
            break
        
def parse_args():
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_link = subparsers.add_parser('link', help='Relink all templates')
    parser_link.add_argument('--limit', help='Limit of servers qty per operation')
    parser_link.add_argument('--debug', default=0, help='1 for debugging. There would be no changes, only text output.')
    parser_link.set_defaults(func=relink_templates)

    parser_clear = subparsers.add_parser('clear', help='Clear orphanded items after linking')
    parser_clear.add_argument('--limit', help='Limit of servers qty per operation')
    parser_clear.add_argument('--debug', default=0, help='1 for debugging. There would be no changes, only text output.')
    parser_clear.set_defaults(func=clear_orphanded)

    return parser.parse_args()

def main():
    config = configparser.ConfigParser()
    config.read(config_file)
    zlogin = config['ZABBIX'].get('login')
    zpassword = config['ZABBIX'].get('password')
    zabbix = ZabbixAPI(zlogin, zpassword)

    args = parse_args()
    args.func(config, args, zabbix)

if __name__ == "__main__":
    main()
