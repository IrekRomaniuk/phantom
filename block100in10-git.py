"""
1.	Anytime the firewall reports a critical or high risk attack originating from an external IP
2.	Check the IP against the trusted list of IP addresses or subnets
3.	Create (or update) ticket in ServiceNow
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import requests
# from pytz import timezone
# Window to count threats
WINDOW = 100
# Number of threats to act upon
LIMIT = 2
# Window to count the same threat again
REPEAT = 300

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    filter_1(container=container)
    return

"""
Not in subnet
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    result = True
    phantom.debug('filter_1() called')    
    sucess, message, trusted = phantom.get_list(list_name='Trusted')
    trusted = [[str(j) for j in i] for i in trusted]
    trusted = [i[0] for i in trusted]
    # phantom.debug('Trusted {}'.format(trusted))
    artifacts_data_1 = phantom.collect2(container=container, datapath=['artifact:*.cef.src'])
    for artifacts_item_1 in artifacts_data_1:
        ip = artifacts_item_1[0]
        if ip:
            if  ip in trusted:
                result = False
            else:
                for net in trusted[1:]:
                    if phantom.valid_net(net):
                        if phantom.address_in_network(ip, net):
                            phantom.debug('ip {} in Trusted net {}: Skipped'.format(ip, net))
                            result = False
                                            
    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            [result, "==", True],
            # ["artifact:*.cef.src", "not in", "custom_list:Trusted"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Not shield
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["filtered-data:filter_1:condition_1:artifact:*.cef.src", "not in", "custom_list:Shields"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        decision_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
check if ticket created
"""
def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    pb_info = phantom.get_playbook_info()
    if not pb_info:
        return
    playbook_name = pb_info[0].get('name', None)
    ticket = phantom.collect(results, "action_result.summary.created_ticket_id")
    artifacts_data_1 = phantom.collect2(container=container, datapath=['artifact:*.cef.src'])
    if ticket:
        ticket = ticket[0]
        phantom.debug('Ticket {}'.format(ticket))
        for artifacts_item_1 in artifacts_data_1:
            if artifacts_item_1:
                if phantom.valid_ip(artifacts_item_1[0]):
                    addr = phantom.get_object(key=str(artifacts_item_1[0]), playbook_name=playbook_name)                   
                    if addr:                
                        addr[0]['value']['ticket'] = ticket
                        #phantom.debug('Saving object {} of type {} with key {}'.format(addr[0], type(addr[0]['value']), artifacts_item_1[0]))
                        phantom.save_object(key=str(artifacts_item_1[0]), value=addr[0]['value'], auto_delete=False, playbook_name=playbook_name)                        
                        
    template = """Ticket
id: {0} number:  {1}"""

    # parameter list for template variable replacement
    parameters = [
        "create_ticket_1:action_result.summary.created_ticket_id",
        "create_ticket_1:action_result.data.*.number",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    return

"""
Count tickets
"""
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called') 
    action = ''
    pb_info = phantom.get_playbook_info()
    name_value = container.get('name', None)
    playbook_name = pb_info[0].get('name', None)
    container_id = container['id'] 
    if not pb_info:
        return    
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef'])       
    phantom.debug('TOTAL number of cef.src artifacts is count: {}'.format(len(filtered_artifacts_data_1))) 
    # local_tz = timezone('America/New_York')
    start = (container['start_time'])[:-3] # start = (container['start_time']).strip('+00')
    start_time = datetime.strptime(start, '%Y-%m-%d %H:%M:%S.%f') # format 2017-10-17 11:32:00.839350
    # start_time = local_tz.localize(start_time)
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        item_1 = filtered_artifacts_item_1[0]['src']
        phantom.debug('ITEM to be processed: {}'.format(item_1))
        if item_1:
            addr = phantom.get_object(key=str(item_1), playbook_name=playbook_name)           
            if not addr:
                phantom.debug('SAVE NEW count: {} {} {} '.format(1, start_time.strftime("%c"), start_time.strftime("%c")))               
                phantom.save_object(key=str(item_1), value={'count': 1, 'start': start_time.strftime("%c"), 'end': start_time.strftime("%c"), 
                                     'description': name_value, 'ticket': '', 'ignore': False}, auto_delete=False, playbook_name=playbook_name) 
            else:
                count = addr[0]['value']['count'] + 1
                ignore = addr[0]['value']['ignore']
                ticket = addr[0]['value']['ticket']                                
                saved_start = addr[0]['value']['start'] 
                saved_start_time = datetime.strptime(saved_start, '%a %b %d %H:%M:%S %Y') # format Mon Oct 16 11:46:30 2017 or '%Y-%m-%d %H:%M:%S.%f' 
                # saved_start_time = local_tz.localize(start_time)
                delta = abs((start_time - saved_start_time)).total_seconds() # .seconds                
                phantom.debug('DECISION start_time {} - saved_start_time {} = {}s '.format(start_time, saved_start_time, delta))
                if ignore and (delta > REPEAT):
                    phantom.debug('IGNORE {} start_time {} - saved_start_time {} = {}s '.format(ignore, start_time, saved_start_time, delta))
                    ignore = False
                    saved_start = start_time.strftime("%c")
                if not ignore:    
                    if (ticket == '') and (delta > WINDOW):
                        saved_start = start_time.strftime("%c")
                        count = 0      
                        phantom.debug('RESET time/co ticket {} delta {}s {} <- {}'.format(ticket, delta, saved_start, start_time.strftime("%c")))  
                    elif (count > LIMIT) and (delta < WINDOW):
                        count = 0
                        saved_start = start_time.strftime("%c")
                        raw = {}
                        cef = {}
                        cef['cs3'] = filtered_artifacts_item_1[0]['cs3']
                        if (ticket == ''):
                            phantom.debug('OPENED {} opened {} {}s ago '.format(item_1, saved_start_time, delta))                            
                            cef['cn1'] = item_1 
                            success, message, artifact_id = phantom.add_artifact(container=container, raw_data=raw, cef_data=cef, label='create', name='ticket', 
                                severity='high', identifier=None, artifact_type='host')                           
                        else:
                            phantom.debug('REOPEN {} reopen {} {}s ago '.format(ticket, saved_start_time, delta))                          
                            cef['cn2'] = item_1 
                            success, message, artifact_id = phantom.add_artifact(container=container, raw_data=raw, cef_data=cef, label='update', name='ticket', 
                                severity='high', identifier=None, artifact_type='host')                            
                        ignore = True
                    phantom.debug('SAVE OLD count: {0} ticket: {1} {2} {3} {4}s'.format(count, ticket, saved_start, start_time.strftime("%c"), delta))  
                    phantom.save_object(key=str(item_1), value={'count': count, 'start': saved_start, 'end': start_time.strftime("%c"), 
                                     'description': name_value, 'ticket': ticket, 'ignore': ignore}, auto_delete=False, playbook_name=playbook_name)  
    
    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        scope='all',
        conditions=[
            ["artifact:*.label", "==", "create"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        create_ticket_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        scope='all',
        conditions=[
            ["artifact:*.label", "==", "update"],
        ])

    # call connected blocks if condition 2 matched
    if matched_artifacts_2 or matched_results_2:
        update_ticket_1(action=action, success=success, container=container, results=results, handle=handle)
        return 
        
    return

def update_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('update_ticket_1() called')
    pb_info = phantom.get_playbook_info()
    if not pb_info:
        return
    playbook_name = pb_info[0].get('name', None)
    ip = ''
    artifacts_data_1 = phantom.collect2(container=container, datapath=['artifact:*.cef.cn2', 'artifact:*.cef.cs3'], scope='all') # , 'artifact:*.id'    
    name_value = container.get('name', None)
    for artifacts_item_1 in artifacts_data_1:
        # phantom.debug('artifact_data_item {}'.format(artifacts_item_1))
        if artifacts_item_1:
            ip = artifacts_item_1[0]
            if phantom.valid_ip(ip):
                ip = str(ip)                   
                addr = phantom.get_object(key=ip, playbook_name=playbook_name)
                if addr:
                    ticket = addr[0]['value']['ticket']                    
                    # collect data for 'update_ticket_1' call
                    parameters = []
                    # build parameters list for 'update_ticket_1' call
                    update = "\"%s\"" % artifacts_item_1[1]  # or "\"{}\"".format(a)
                    parameters.append({
                        'id': ticket,
                        'table': "u_security_engineering_request",
                        'fields': "{\"state\": \"1\", \"work_notes\": \"%s\" }" % artifacts_item_1[1],
                        # 'fields': "{\"work_notes\": \"Updated\" }", 
                        # 'fields': "{\"update\": {\"state\": \"open\", \"work_notes\": \"%s\"}}" % artifacts_item_1[1],
                        # 'fields': "{\"priority\": \"2\",\"impact\": \"2\",\"comments\": \"Anything can go here\"}",
                        'vault_id': "",
                    })
                    phantom.debug('update ticket {} for ip {}: {}'.format(ticket, ip, update))
                    phantom.act("update ticket", parameters=parameters, assets=['servicenow'], name="update_ticket_1")    
    
    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):    
    phantom.debug('create_ticket_1() called')
    ip = ''
    artifacts_data_1 = phantom.collect2(container=container, datapath=['artifact:*.cef.cn1', 'artifact:*.cef.cs3'], scope='all') # , 'artifact:*.id'    
    name_value = container.get('name', None) 
    # phantom.debug('artifact_data {}'.format(artifacts_data_1))
    for artifacts_item_1 in artifacts_data_1:
        # phantom.debug('artifact_data_item {}'.format(artifacts_item_1))
        if artifacts_item_1:
            ip = artifacts_item_1[0]
            if phantom.valid_ip(ip):
                ip = str(ip)
                # collect data for 'create_ticket_1' call
                pb_info = phantom.get_playbook_info()                
                playbook_name = pb_info[0].get('name', None)
                parameters = []
                # build parameters list for 'create_ticket_1' call
                parameters.append({
                    'short_description': artifacts_item_1[0] + ' -> ' + artifacts_item_1[1],
                    'description': "Source IP address: " + ip,
                    'table': "u_security_engineering_request", # 
                    'fields': "{\"priority\": \"2\",\"impact\": \"2\",\"comments\": \"Playbook name: %s\"}" %playbook_name,
                    'vault_id': "",
                })
                phantom.debug('create ticket for ip {} '.format(ip))
                # if len(ip)>0:
                phantom.act("create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_1", callback=format_1) # callback=get_ticket_id,
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    phantom.remove_list(list_name='Threats-Reported', empty_list=True)
    phantom.remove_list(list_name='Threats-Repeated', empty_list=True)
    # phantom.debug("create_ticket_1:action_result.parameter.id")
    phantom.debug(phantom.get_format_data(name="format_1"))        
    
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
