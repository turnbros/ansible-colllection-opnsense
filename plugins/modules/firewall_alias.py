#!/usr/bin/python

# Copyright: (c) 2020, Your Name <YourName@example.org>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

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
    parent:
        description: Name of other alias who will contain this alias (nested)
        required: false
        type: str
        default: None
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
author:
    - Your Name (@yourGitHubHandle)
'''

EXAMPLES = r'''
- name: Create new alias
  turnbros.opnsense.firewall_alias:
    parent: some_other_alias
    name: hello_world
    description: a description for your alias
    type: port
    content:
        - 42
        - another_port_alias
    enabled: true
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

def run_module():

    module_args = dict(
        api_key=dict(type='str', required=True),
        api_secret=dict(type='str', required=True, no_log=True),
        api_scheme=dict(type='str', required=False, default="https"),
        api_host=dict(type='str', required=True),
        api_port=dict(type='int', required=False, default=443),
        api_ca_path=dict(type='str', required=False, default=None),
        parent=dict(type='str', required=False, default=None),
        name=dict(type='str', required=True),
        description=dict(type='str', required=False, default=None),
        type=dict(type='str', required=False, choices=['host', 'network', 'port', 'url'], default=None),
        content=dict(type='list', required=False, default=None),
        enabled=dict(type='bool', required=False, default=None),
    )

    result = dict(
        changed=False,
        alias={},
        diff={
            'before': '',
            'after': '',
        }
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    if module.check_mode:
        module.exit_json(**result)

    alias_controller = Opnsense(api_key=module_args['api_key'],
                                api_secret=module_args['api_secret'],
                                scheme=module_args['api_scheme'],
                                host=module_args['api_host'],
                                port=module_args['api_port'],
                                ca_path=module_args['api_ca_path']
                                ).firewall.alias_controller

    alias_parent = module_args['parent']
    alias_name = module_args['name']
    alias_description = module_args['description']
    alias_type = module_args['type']
    alias_content = module_args['content']
    alias_enabled = module_args['enabled']

    alias_controller.get_alias_uuid()

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)
    result['original_message'] = module.params['name']
    result['message'] = 'goodbye'
    result['my_useful_info'] = {
        'foo': 'bar',
        'answer': 42,
    }
    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results



    module.exit_json(**result)

def main():
    run_module()


if __name__ == '__main__':
    main()