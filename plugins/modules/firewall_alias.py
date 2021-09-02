#!/usr/bin/python

# Copyright: (c) 2020, Your Name <YourName@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json

DOCUMENTATION = r'''
---
module: firewall_alias
short_description: Manage an Opnsense firewall alias
version_added: "1.0.0"
description: This module manages an Opnsense firewall alias
options:
    api_key:
        description: The API key used to authenticate with Opnsense
        required: true
        type: str
    api_secret:
        description: The API secret used to authenticate with Opnsense
        required: true
        type: str
    api_scheme:
        description: The HTTP scheme to use when connecting to Opnsense
        required: false
        default: https
        type: str
    api_host:
        description: The hostname or IP of the Opnsense device
        required: true
        type: str
    api_port:
        description: The port to connection to the Opnsense device on
        required: false
        default: 443
        type: int
    api_ca_path:
        description: A path to the CA files used to validate the Opnsense cert
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
from opnsense_api.util import AliasType

def run_module():

  module_args = dict(
    api_key=dict(type='str', required=True),
    api_secret=dict(type='str', required=True, no_log=True),
    api_scheme=dict(type='str', required=False, default="https"),
    api_host=dict(type='str', required=True),
    api_port=dict(type='int', required=False, default=443),
    api_ca_path=dict(type='str', required=False, default=None),

    name=dict(type='str', required=True),
    description=dict(type='str', required=False, default=""),
    type=dict(type='str', required=True, choices=['host', 'network', 'port', 'url']),
    content=dict(type='list', required=False, default=[]),
    enabled=dict(type='bool', required=False, default=True),
    state=dict(type='str', required=False, choices=['present', 'absent'], default='present'),
  )

  result = dict(
    changed=False,
    alias=dict(),
    diff=dict(
      before=dict(),
      after=dict()
    )
  )

  module = AnsibleModule(
    argument_spec=module_args,
    # TODO: This should really support checkmode. I just don't have time right now.
    supports_check_mode=True
  )

  # Open a connection to the Opnsense device and return the alias controller
  alias_controller = Opnsense(api_key=module.params['api_key'],
                              api_secret=module.params['api_secret'],
                              scheme=module.params['api_scheme'],
                              host=module.params['api_host'],
                              port=module.params['api_port'],
                              ca_path=module.params['api_ca_path']
                              ).firewall.alias_controller

  # Get all the module params
  alias_name = module.params['name']
  alias_uuid = alias_controller.get_alias_uuid(alias_name)
  alias_description = module.params['description']
  alias_type = module.params['type']
  alias_content = module.params['content']
  alias_enabled = bool(int(module.params['enabled']))
  alias_state = module.params['state']

  # Get the alias if the get_alias_uuid call returned a value
  alias = None
  if alias_uuid is not None:
    alias = alias_controller.get_alias(alias_uuid)

  #################################
  ##       Delete Alias          ##
  #################################
  if alias_state == "absent":
    if alias_uuid is not None:
      if not module.check_mode:
        alias_controller.delete_alias(alias_uuid)

      result["changed"] = True
      result["alias"] = alias
      result["diff"]["before"] = alias
      result["diff"]["after"] = dict()

    module.exit_json(**result)

  if alias_state == "present":

    #################################
    ##       Create Alias          ##
    #################################
    if alias_uuid is None:
      if not module.check_mode:
        response = alias_controller.add_alias(
          name=alias_name,
          alias_type=AliasType[alias_type.upper()],
          description=alias_description,
          content=alias_content,
          enabled=alias_enabled
        )
        if (response['result'] == 'saved') and ('uuid' in response):
          alias = alias_controller.get_alias(response['uuid'])
        else:
          module.fail_json(f"Failed to create alias with response: {json.dumps(response)}")

      else:
        alias = dict(
          name=alias_name,
          alias_type=alias_type,
          description=alias_description,
          content=alias_content,
          enabled=alias_enabled
        )

      result["changed"] = True
      result["alias"] = alias
      result["diff"]["before"] = dict()
      result["diff"]["after"] = alias

    #################################
    ##       Update Alias          ##
    #################################
    else:

      # Figure out if we need to update the alias
      update_needed = False
      if (
        (alias['type'] != alias_type.upper())
        or (alias['description'] != alias_description)
        or (alias['content'] != [str(item) for item in alias_content])
        or (alias['enabled'] != alias_enabled)
      ): update_needed = True

      # Setting this here so the editor stops yelling at me about
      # using it before its set.
      updated_alias = alias

      # Make the change via the API, but ONLY if actually needed.
      if not module.check_mode and update_needed :
        response = alias_controller.set_alias(
          uuid=alias_uuid,
          name=alias_name,
          alias_type=AliasType[alias_type.upper()],
          description=alias_description,
          content=alias_content,
          enabled=alias_enabled
        )

        if response['result'] == 'saved':
          updated_alias = alias_controller.get_alias(alias_uuid)
        else:
          module.fail_json(f"Failed to update the alias with response: {json.dumps(response)}")
      else:
        updated_alias = dict(
          uuid=alias_uuid,
          name=alias_name,
          alias_type=alias_type.upper(),
          description=alias_description,
          content=alias_content,
          enabled=alias_enabled
        )

      result["changed"] = update_needed
      result["alias"] = updated_alias
      result["diff"]["before"] = alias
      result["diff"]["after"] = updated_alias

  module.exit_json(**result)

def main():
  run_module()


if __name__ == '__main__':
  main()