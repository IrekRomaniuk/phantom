"""
new version of 'phish' playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import re
from urllib import unquote
from urlparse import urlparse
import html.parser
import string

EXCLUDED=['w3.org','microsoft.com']

def test_params(container, datapath, key_name):
    params = []
    items = set(phantom.collect(container, datapath, scope='all'))
    for item in items:
        params.append({key_name:item}) 
    return params
def decodev2 (rewrittenurl):
	match = re.search(r'u=(.+?)&[dc]=',rewrittenurl)
	if match:
		specialencodedurl = match.group(1)
		trans = string.maketrans('-_', '%/')
		urlencodedurl = specialencodedurl.translate(trans)
		htmlencodedurl = unquote(urlencodedurl)
		url = html.parser.HTMLParser().unescape(htmlencodedurl)
		return url
	else:
		return 'Error parsing URL'

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    #vault = test_params(container, 'artifact:*.cef.vaultId','vault')
    email = test_params(container, 'artifact:*.cef.fromEmail','email')
    file_hashs = test_params(container, 'artifact:*.cef.cs6', 'hash')
    file_names = test_params(container, 'artifact:*.cef.fileName', 'file')
    urls = test_params(container, 'artifact:*.cef.requestURL', 'url')
    domains = test_params(container,'artifact:*.cef.destinationDnsDomain', 'domain')
    
    phantom.debug('emails: {} files: {}'.format(email, file_names))
    phantom.debug('urls: {}'.format(urls))

    #if email:
    lookup_email_4(container=container)
    
    file_reputation_1(container=container)

    return

def lookup_email_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('lookup_email_4() called')

    # collect data for 'lookup_email_4' call
    # container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fromEmail', 'artifact:*.id'])
    results_email = phantom.collect(container,"artifact:*.cef.fromEmail", scope='all')
    email = results_email[0]
    phantom.debug('email: {}'.format(email))
    
    parameters = []

    parameters.append({'email': re.search(r'<(.*?)>', email).group(1)})    
    phantom.act("lookup email", parameters=parameters, app={ "name": 'Have I Been Pwned' }, name="lookup_email_4", callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')
    # always call for now
    join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
    return
    #data=phantom.collect(results,"action_result.data.*.PwnCount")
    #phantom.debug(data)

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["lookup_email_4:action_result.summary.total_breaches", ">", "1"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
        #send_email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')
    # always call for now
    join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
    return
    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        join_send_email_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashSha256', 'artifact:*.id','artifact:*.cef.isInline'])

    parameters = []
    isInline = 'false'
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        #phantom.debug('item: {}'.format(container_item))
        if container_item[0]:
            if container_item[2]:
                isInline = container_item[2]
            phantom.debug('all files: {} id: {} isInline: {}'.format(container_item[0], container_item[1], container_item[2]))                
            if isInline == 'false': #.lower()
                phantom.debug('att files: {} id: {} isInline: {}'.format(container_item[0], container_item[1], isInline))
                parameters.append({
                    'hash': container_item[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': container_item[1]},
                })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=decision_2, name="file_reputation_1")

    return

def send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('send_email_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_1' call
    results_lookup_email = phantom.collect2(container=container, datapath=['lookup_email_4:action_result.summary.total_breaches','lookup_email_4:action_result.data.*.Title', 'lookup_email_4:action_result.data.*.BreachDate', 'lookup_email_4:action_result.parameter.context.artifact_id'], action_results=results)
    #phantom.debug('{}'.format(results_data_1))
    results_email = phantom.collect(container,"artifact:*.cef.fromEmail", scope='all')
    email = results_email[0]
    results_urls = phantom.collect(container,"artifact:*.cef.requestURL", scope='all')
    urls=set([])
    for url in results_urls:
        #o=urlparse(url)
        #phantom.debug('url netloc: {}'.format(o.netloc))
        urls.add(url)
    #urls=list(set(urls))   
    results_files = phantom.collect(container,"artifact:*.cef.fileName", scope='all')
    files=[]
    for file in results_files:
        files.append(file)

    results_reputation = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.summary.positives'],action_results=results)    
    positives=[]
    message=''
    for positive in results_reputation:
        phantom.debug('positive: {}'.format(positive[0]))
        if positive[0]>0:
            message=' !!! infected attachment identified'
        
        positives.append(positive)

    phantom.debug('email: {} reputation: {}'.format(email, zip(files, positives)))
   
    parameters = []
    body = "PhishReports summary:\n\nBreaches:\n"
    total1=0
    _id=0
    # build parameters list for 'send_email_1' call
    for results_item_email in results_lookup_email:
        if results_item_email[0]:
            phantom.debug('Breaches: {0}->{1}->{2}->{3}'.format(results_item_email[0],results_item_email[1],results_item_email[2],results_item_email[3]))
            body = body + str(results_item_email[1]) + ' on ' + str(results_item_email[2]) + '\n'
            total1 = results_item_email[0]
            _id = results_item_email[3]
    if len(files)>0: 
        body = body + '\nReputations:\n'        
        for item in zip(files, positives):
            body = body + str(item[0]) + ' has ' + str(item[1][0])+ ' positives\n'   
    if len(urls)>0: 
        phantom.debug('urls type: {}'.format(type(urls)))
        body = body + '\nUrls:\n' 
        santized_urls=[]
        for index,item in enumerate(urls):
            if item.startswith( 'http' ):
                if not any(substring in item for substring in EXCLUDED):
                    if 'urldefense.proofpoint.com/v2' in item:
                        item=decodev2(item) + ' <- urldefense.proofpoint.com/v2' #<a href="url">link text</a>      
                    sanitized_item=item.split(' ')[0]   
                    if sanitized_item not in santized_urls:
                        santized_urls.append(sanitized_item)
                        #phantom.debug('item {} added'.format(sanitized_item))
                        body = body + '    - ' + str(sanitized_item)+'\n'        

    #phantom.debug('{}'.format(santized_urls))
    phantom.debug('{}'.format(body))   
    
    if 'romaniuk' in email.lower():
        to="me@example.com"
    else:
        to="me@example.com"
            
    parameters.append({
                'from': "phantom-dev@example.com",
                'to': to,
                'subject': 'PhishReports for ' + email + message,
                'body': body,
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': _id},
            })
    phantom.debug('Breaches: {} Postives: {}'.format(int(total1),positive[0]))
    if int(total1)>=0 or positive[0]>=0:
        phantom.act("send email", parameters=parameters, app={ "name": 'SMTP' }, name="send_email_1")

    return

def join_send_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_send_email_1() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'lookup_email_4', 'file_reputation_1' ]):
        
        # call connected block "send_email_1"
        send_email_1(container=container, handle=handle)
    
    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')

    return