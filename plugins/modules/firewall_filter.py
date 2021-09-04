#!/usr/bin/python

# Copyright: (c) 2020, Your Name <YourName@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

from typing import Union

DOCUMENTATION = r'''
---
module: firewall_filter
short_description: Manage an Opnsense firewall alias
version_added: "1.0.0"
description: This module manages an Opnsense firewall alias
options:
    api_key:
        description: The API key used to authenticate with Opnsense
        required: false
        type: str
    api_secret:
        description: The API secret used to authenticate with Opnsense
        required: false
        type: str
    api_scheme:
        description: The HTTP scheme to use when connecting to Opnsense
        required: false
        type: str
    api_host:
        description: The hostname or IP of the Opnsense device
        required: false
        type: str
    api_port:
        description: The port to connection to the Opnsense device on
        required: false
        type: int
    api_ca_path:
        description: A path to the CA files used to validate the Opnsense cert
        required: false
        type: str
    api_ca_content:
        description: The content of a CA cert that can be used to validate the Opnsense cert
        required: false
        type: str
    name:
        description: Name of the alias
        required: true
        type: str
    description:
        description: Description of the alias
        required: false
        type: str
        default: None
    type:
        description: Type of the alias
        required: false
        type: str
    content:
        description: The content of this alias (IP, Cidr, url, ...)
        required: false
        type: list
        default: []
    enabled:
        description: This is the message to send to the test module.
        required: false
        type: bool
        default: true
    state:
        description: Determines wether or not this alias should exist.
        required: false
        type: str
        default: present
author:
    - Your Name (@yourGitHubHandle)
'''

EXAMPLES = r'''
- name: Create new alias
  turnbros.opnsense.firewall_alias:
    name: hello_world
    description: a description for your alias
    type: port
    content:
        - 42
        - another_port_alias
    enabled: true
    state: present
'''

RETURN = r'''
# These are examples of possible return values, and in general should use other names for return values.
original_message:
    description: The original name param that was passed in.
    type: str
    returned: always
    sample: 'hello world'
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
my_useful_info:
    description: The dictionary containing information about your system.
    type: dict
    returned: always
    sample: {
        'foo': 'bar',
        'answer': 42,
    }
'''

from ansible.module_utils.basic import AnsibleModule

from opnsense_api import Opnsense
from opnsense_api.firewall.filter_controller import Filter


def lookup_rule(module: AnsibleModule, filter_controller: Filter, uuid:str, description:str) -> Union[dict, None]:
  # If the UUID was supplied, then just get the rule using that.
  if uuid is not None:
    found_rule = filter_controller.get_rule(uuid)

    if found_rule is None:
      return None

  # If the UUID wasn't supplied we'll try perform a match.
  else:
    matched_rules = filter_controller.match_rule_by_attributes(**{"description": description})

    # If we didn't match anything, then we just return None
    # We don't fail here because the rule not existing might be what we want.
    if len(matched_rules) == 0:
      return None

    # If we found more than one matching rule, we'll fail.
    if len(matched_rules) > 1:
      result = dict(
        changed=False,
        match_attributes={"description": description},
        matched_module=matched_rules
      )
      module.fail_json(msg="Multiple modules matched", **result)

    return matched_rules[0]

def parse_filter_rule_spec(params: dict) -> dict:
  return {
      "uuid": params['uuid'],
      "description": params['description'],
      "action": params['action'],
      "direction": params['direction'],
      "protocol": params['protocol'],
      "destination_port": params['destination_port'],
      "interface": params['interface'],
      "source_net": params['source_net'],
      "source_port": params['source_port'],
      "destination_net": params['destination_net'],
      "gateway": params['gateway'],
      "source_not": params['source_not'],
      "destination_not": params['destination_not'],
      "sequence": params['sequence'],
      "enabled": params['enabled'],
      "quick": params['quick'],
      "log": params['log'],
      "ipprotocol": params['ipprotocol'],
    }

import sys

def run_module():

  module_args = dict(
    api_key=dict(type='str', required=False, default=None),
    api_secret=dict(type='str', required=False, default=None, no_log=True),
    api_scheme=dict(type='str', required=False, default=None),
    api_host=dict(type='str', required=False, default=None),
    api_port=dict(type='int', required=False, default=None),
    api_ca_path=dict(type='str', required=False, default=None),
    api_ca_content=dict(type='str', required=False, default=None),
    uuid=dict(type='str', required=False, default=None),
    action=dict(type='str', required=False, choices=['pass', 'block', 'reject', None], default=None),
    direction=dict(type='str', required=False, choices=['in', 'out', None], default=None),
    interface=dict(type='list', required=False, default=None),
    protocol=dict(type='str', required=False, default=None),
    source_net=dict(type='str', required=False, default=None),
    source_port=dict(type='int', required=False, default=None),
    destination_net=dict(type='str', required=False, default=None),
    destination_port=dict(type='int', required=False, default=None),
    gateway=dict(type='str', required=False, default=None),
    source_not=dict(type='bool', required=False, default=None),
    destination_not=dict(type='bool', required=False, default=None),
    sequence=dict(type='int', required=False, default=None),
    description=dict(type='str', required=False, default=None),
    enabled=dict(type='bool', required=False, default=None),
    quick=dict(type='bool', required=False, default=None),
    log=dict(type='bool', required=False, default=None),
    ipprotocol=dict(type='str', required=False, choices=['inet', 'inet6', None], default=None),
    state=dict(type='str', required=False, choices=['present', 'absent'], default='present'),
  )

  result = {
    "changed": False,
    "rule": {},
    "diff": {
      "before": {},
      "after": {}
    }
  }

  module = AnsibleModule(
    argument_spec=module_args,
    supports_check_mode=True
  )

  # Open a connection to the Opnsense device and return the alias controller
  filter_controller = Opnsense(api_key=module.params['api_key'],
                              api_secret=module.params['api_secret'],
                              scheme=module.params['api_scheme'],
                              host=module.params['api_host'],
                              port=module.params['api_port'],
                              ca_path=module.params['api_ca_path'],
                              ca_content=module.params['api_ca_content']
                              ).firewall.filter_controller

  ##########################
  ##      Lookup Rule     ##
  ##########################

  # Parse the input params into a FilterRule object
  filter_rule_spec = parse_filter_rule_spec(module.params)

  # Lookup the filter rule and return a FilterRule object
  filter_rule = lookup_rule(module, filter_controller, module.params['uuid'], module.params['description'])

  # We can go ahead and set the before state here since we know what it is
  if filter_rule is not None:
    result["diff"]["before"] = filter_rule.copy()

  ##########################
  ##     Delete Rule      ##
  ##########################

  # If the rule state is absent we can just exit.
  if (filter_rule is None) and (module.params['state'] == "absent"):
    module.exit_json(**result)

  # In this case the rule would exist and would need to be deleted.
  if (filter_rule is not None) and (module.params['state'] == "absent"):

    result["changed"] = True

    # Safety first. Make sure we're not in check mode.
    if not module.check_mode:
      # Toto, I've a feeling we're not in check mode anymore.
      filter_controller.delete_rule(filter_rule['uuid'])

    module.exit_json(**result)

  ###########################
  ## Create Or Update Rule ##
  ###########################

  # Create a new firewall filter rule
  if module.params['state'] == "present":
    if not module.check_mode:
      result['diff']['after'] = filter_controller.add_or_set_rule(filter_rule["uuid"],
                                                                  action=filter_rule_spec["action"],
                                                                  direction=filter_rule_spec["direction"],
                                                                  interface=filter_rule_spec["interface"],
                                                                  protocol=filter_rule_spec["protocol"],
                                                                  source_net=filter_rule_spec["source_net"],
                                                                  source_port=filter_rule_spec["source_port"],
                                                                  destination_net=filter_rule_spec["destination_net"],
                                                                  destination_port=filter_rule_spec["destination_port"],
                                                                  gateway=filter_rule_spec["gateway"],
                                                                  source_not=filter_rule_spec["source_not"],
                                                                  destination_not=filter_rule_spec["destination_not"],
                                                                  sequence=filter_rule_spec["sequence"],
                                                                  description=filter_rule_spec["description"],
                                                                  enabled=filter_rule_spec["enabled"],
                                                                  quick=filter_rule_spec["quick"],
                                                                  log=filter_rule_spec["log"],
                                                                  ipprotocol=filter_rule_spec["ipprotocol"])
    else:
      result['diff']['after'] = filter_rule

  if result['diff']['after'] != result['diff']['before']:
    result["changed"] = True

  module.exit_json(**result)

def main():
  run_module()


if __name__ == '__main__':
  main()