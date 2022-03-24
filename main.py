#!/usr/bin/env python3
import argparse
import sys
import numpy as np
import pandas as pd
from utils.logger_main import log
from utils.api_client import API_client

client = API_client
all_columns = ['No.', 'Enabled', 'Hits', 'Name', 'Source', 'Destination', 'Service', 'Action', 'Track', 'Install-On', 'Time', 'Comments']  

def export_policies():
  policies = {}
  response = client.run_command("show-packages", payload={"limit": 500, "details-level": "full"})
  for policy in response['packages']:
    log.info(f"[+] Policy: {policy['name']}")
    log.info(f"[+] FW: {[ fw['name'] for fw in policy['installation-targets'] ]}")
    policies[policy['name']] = {}
    policies[policy['name']]['Firewalls'] = [ fw['name'] for fw in policy['installation-targets'] ]
    policies[policy['name']]['Layers'] = [ layer['name'] for layer in policy['access-layers'] ]
    policies[policy['name']]['Rules'] = [{ layer['name']: export_rules(layer['name']) for layer in policy['access-layers'] }]
  return policies


def export_rules(layer, limit=500, parent_rule_number=None) -> list:
  rules = []
  log.info(f"[+] Layer: {layer}")
  payload={"name": layer,
         "offset": 0,
         "limit": limit, 
         "show-hits": True, 
         "use-object-dictionary": False}
  response = client.run_command("show-access-rulebase", payload=payload)
  rules.extend(parse_rules(response, parent_rule_number))
  for offset in range(limit, response['total'], limit):
    payload['offset'] = offset
    response = client.run_command("show-access-rulebase", payload=payload)
    rules.extend(parse_rules(response, parent_rule_number))
  return rules

def parse_rules(rulebase, parent_rule_number) -> list:
  rules = []
  for rule in rulebase['rulebase']:
    tmp_rule = {}
    if rule.get('rulebase'):
      rules.extend(parse_rules(rule, parent_rule_number))
    elif rule['type'] == 'access-rule':
      rule_number = rule['rule-number'] if parent_rule_number == None else f"{parent_rule_number}.{rule['rule-number']}"
      tmp_rule['No.'] = str(rule_number)
      tmp_rule['Enabled'] = rule['enabled']
      tmp_rule['Hits'] = rule['hits']['value']
      tmp_rule['Name'] = rule['name'] if rule.get('name') else ''
      tmp_rule['Source'] = '<br/>'.join([value['name'] for value in rule['source']])
      tmp_rule['Destination'] = '<br/>'.join([value['name'] for value in rule['destination']])
      tmp_rule['Service'] = '<br/>'.join([value['name'] for value in rule['service']])
      tmp_rule['Action'] = rule['action']['name']
      tmp_rule['Track'] = rule['track']['type']['name']
      tmp_rule['Install-On'] = '<br/>'.join([value['name'] for value in rule['install-on']])
      tmp_rule['Time'] = '<br/>'.join([value['name'] for value in rule['time']])
      tmp_rule['Comments'] = str(rule['comments']).replace('\n', '<br/>') if rule.get('comments') else ''
      rules.append(tmp_rule)
      if rule.get('inline-layer'):
        rules.extend(export_rules(rule['inline-layer']['name'], parent_rule_number=rule_number))
  return rules

def render_html(policy: str, firewalls: str, matched_conditions: list, number_of_rules: int):
  html_head = """
  <html>
    <head>
      <style>
        table, th, td { font-size:10pt; border:1px solid black; border-collapse:collapse; text-align:left; }
        th, td { padding: 1px; padding-left: 2px; padding-right: 2px; }
        thead { background-color:dodgerblue; color:white; border:1px; }
        tr:nth-child(even) { background-color: #f2f2f2; }
      </style>
    </head>
    <body>
  """

  html_foot = """
    </body>
  </html>
  """
  filename = f"{policy.strip()}.html"
  with open(filename, 'w') as f:
    f.write(html_head)
    f.write("<br>")
    f.write(f"<h2>Policy: {policy}</h2>")
    f.write(f"<h3>Firewalls: {firewalls}</h3>")
    f.write(f"<h3>Rule Base: {number_of_rules}</h3>")
    for item in matched_conditions:
      for layer, check in item.items():
        f.write(f"<h4>Layer: {layer}</h4>")
        for k, v in check.items():
          f.write(f"<h4>Check: {k}</h4>")
          f.write(v)
          f.write("<br>")
    f.write(html_foot)
  log.info(f"[+] Created file: {filename}")
  return

def get_dataframe_html(header, data):
  num = np.array(data, dtype=object)
  df = pd.DataFrame(columns=header) if len(data) == 0 else pd.DataFrame(num, columns=header)
  s = df.style.set_table_styles(
    [{'selector': 'tr:nth-of-type(odd)',
      'props': [('background', '#eee')]}, 
     {'selector': 'tr:nth-of-type(even)',
      'props': [('background', 'white')]},
     {'selector': 'th',
      'props': [('background', '#606060'), 
                ('color', 'white'),
                ('font-family', 'verdana')]},
     {'selector': 'td',
      'props': [('font-family', 'verdana')]},
     {'selector': 'thead',
      'props': 'background-color:dodgerblue; color:white; border:3px solid red;'},
    ]
    )
  #html = df.to_html(classes='table table-stripped', index=False)
  #print(df.style.render())
  return df.to_html(classes='table table-stripped', index=False, escape=False)

def banner():
  logo = \
    """
    +-+-+-+-+-+-+-+
    |S|m|a|r|d|i|t|
    +-+-+-+-+-+-+-+

    By: The Machine & The API Guy
    """
  print(logo)
    
def main():
    banner()
    global client
    policies = {}
    
    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", default="admin")
    parser.add_argument("--port", default="443")
    parser.add_argument("-p", "--password", default="")
    parser.add_argument("-m", "--management", default="")
    parser.add_argument("-d", "--domain", default="")
    #parser.add_argument("-l", "--policy_layer", default="")

    parsed_args = parser.parse_args()
    
    client = API_client(api_server=parsed_args.management, user=parsed_args.user,
                        password=parsed_args.password, port=parsed_args.port, domain=parsed_args.domain)
    #policy_layer = parsed_args.policy_layer

    client.login()
    try:
        # get all policies as key and associated layers in a list.
        policies = export_policies()
        log.info('Policies and Rules exported successfully')
    except Exception as exc:
        log.exception(exc)
        sys.exit(1)
    
    conditional_checks = [
      {'name': 'Zero Hits', 'filter': lambda rule: rule["Hits"] == 0 and rule['Action'] != 'Drop', 'columns': all_columns},
      {'name': 'Over 1 Million Hits', 'filter': lambda rule: rule["Hits"] >= 1_000_000 and rule['Action'] != 'Drop', 'columns': all_columns},
      {'name': 'Disabled Rules', 'filter': lambda rule: rule["Enabled"] == False and rule['Action'] != 'Drop', 'columns': all_columns},
      {'name': 'Parent Rules with Any', 'filter': lambda rule: any('Any' in rule[field] for field in ["Source", "Destination", "Service"]) and '.' not in rule['No.'] and rule['Action'] != 'Drop', 'columns': all_columns},
      {'name': 'Inline-Layer Rules with Any', 'filter': lambda rule: any('Any' in rule[field] for field in ["Source", "Destination", "Service"]) and '.' in rule['No.'] and rule['Action'] != 'Drop', 'columns': all_columns}
      ]
    
    for pk, pv in policies.items():
      matched_conditions = []
      number_of_rules = 0
      for layer in pv['Rules']:
        for rk, rules in layer.items():
          number_of_rules += len(rules)
          matched_condition = {}
          for check in conditional_checks:
            filtered_rules = [*filter(check["filter"], rules)]
            header = check['columns']
            data = []
            if len(filtered_rules) > 0:
              data = [[item.get(key) for key in check["columns"]] for item in filtered_rules]
            matched_condition[check['name']] = get_dataframe_html(header, data)
          matched_conditions.append({rk: matched_condition})
      log.info(f"[*] Policy {pk} has {number_of_rules} rules")
      firewalls = ', '.join(pv['Firewalls'])
      render_html(pk, firewalls, matched_conditions, number_of_rules)

    # logout
    client.logout()

if __name__ == "__main__":
    main()
