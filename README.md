# Ansible Collection - turnbros.opnsense

A collection of Ansible modules for managing an Opnsense device.

## Getting Started
```yaml
- hosts: localhost
  connection: local
  gather_facts: no
  tasks:
    - name: Create new alias
      firewall_alias:
        api_key: my_opnsense_api_key
        api_secret: my_opnsense_api_secret
        api_host: my_opnsense_device_ip_or_host
        api_ca_path: /path/to/opnsense/ca/cert_bundle.pem
        name: hello_alias
        description: a description for your alias
        type: port
        content:
            - 42
        enabled: true
        state: present
        
    - name: Create another alias
      firewall_alias:
        api_key: my_opnsense_api_key
        api_secret: my_opnsense_api_secret
        api_host: my_opnsense_device_ip_or_host
        api_ca_path: /path/to/opnsense/ca/cert_bundle.pem
        name: hello_again_alias
        description: a description for your alias
        type: port
        content:
            - 24
            - hello_alias
        enabled: true
        state: present
```