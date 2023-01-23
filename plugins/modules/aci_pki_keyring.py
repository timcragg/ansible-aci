#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_pki_keyring
short_description: Manage PKI Keyrings (pki:KeyRing)
description:
- Manage PKI Keyrings on Cisco ACI fabrics.
options:
  name:
    description:
    - The name of the PKI Keyring.
    type: str
    aliases: [ keyring ]
  description:
    description: Description of the Keyring
    type: str
    aliases: [ descr ]
  certificate:
    description: Certificate for the Keyring in PEM format
    type: str
    aliases: [ cert ]
  modulus:
    description: Length of the encryption key. The APIC defaults to mod2048.
    type: int
    choices: [ mod512, mod1024, mod1536, mod2048 ]
  trustpoint:
    description: PKI Trustpoint to bind the Keyring with
    type: string
  state:
    description:
    - Use C(present) or C(absent) for adding or removing.
    - Use C(query) for listing an object or multiple objects.
    type: str
    choices: [ absent, present, query ]
    default: present
extends_documentation_fragment:
- cisco.aci.aci

author:
- Tim Cragg (@timcragg)
"""

EXAMPLES = r"""
- name: Add a PKI Keyring
  cisco.aci.aci_pki_keyring:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_keyring
    description: "Anstest Keyring"
    modulus: mod1536
    state: present
  delegate_to: localhost

- name: Query a PKI Keyring
  cisco.aci.aci_pki_keyring:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_keyring
    state: query
  delegate_to: localhost

- name: Query all PKI Keyrings
  cisco.aci.aci_pki_keyring:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a PKI Keyring
  cisco.aci.aci_pki_keyring:
    host: apic
    username: admin
    password: SomeSecretPassword
    name: anstest_keyring
    state: absent
  delegate_to: localhost
"""

RETURN = r"""
current:
  description: The existing configuration from the APIC after the module has finished
  returned: success
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production environment",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
error:
  description: The error information as returned from the APIC
  returned: failure
  type: dict
  sample:
    {
        "code": "122",
        "text": "unknown managed object class foo"
    }
raw:
  description: The raw output returned by the APIC REST API (xml or json)
  returned: parse error
  type: str
  sample: '<?xml version="1.0" encoding="UTF-8"?><imdata totalCount="1"><error code="122" text="unknown managed object class foo"/></imdata>'
sent:
  description: The actual/minimal configuration pushed to the APIC
  returned: info
  type: list
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment"
            }
        }
    }
previous:
  description: The original configuration from the APIC before the module has started
  returned: info
  type: list
  sample:
    [
        {
            "fvTenant": {
                "attributes": {
                    "descr": "Production",
                    "dn": "uni/tn-production",
                    "name": "production",
                    "nameAlias": "",
                    "ownerKey": "",
                    "ownerTag": ""
                }
            }
        }
    ]
proposed:
  description: The assembled configuration from the user-provided parameters
  returned: info
  type: dict
  sample:
    {
        "fvTenant": {
            "attributes": {
                "descr": "Production environment",
                "name": "production"
            }
        }
    }
filter_string:
  description: The filter string used for the request
  returned: failure or debug
  type: str
  sample: ?rsp-prop-include=config-only
method:
  description: The HTTP method used for the request to the APIC
  returned: failure or debug
  type: str
  sample: POST
response:
  description: The HTTP response from the APIC
  returned: failure or debug
  type: str
  sample: OK (30 bytes)
status:
  description: The HTTP status from the APIC
  returned: failure or debug
  type: int
  sample: 200
url:
  description: The HTTP url used for the request to the APIC
  returned: failure or debug
  type: str
  sample: https://10.11.12.13/api/mo/uni/tn-production.json
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.aci.plugins.module_utils.aci import ACIModule, aci_argument_spec


def main():
    argument_spec = aci_argument_spec()
    argument_spec.update(
        name=dict(type="str", aliases=["keyring"]),
        description=dict(type="str", aliases=["descr"]),
        certificate=dict(type="str", aliases=["cert"]),
        modulus=dict(type="str", choices=["mod512", "mod1024", "mod1536", "mod2048"]),
        trustpoint=dict(type="str"),
        state=dict(type="str", default="present", choices=["absent", "present", "query"]),
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ["state", "absent", ["name"]],
            ["state", "present", ["name"]],
        ],
    )

    name = module.params.get("name")
    description = module.params.get("description")
    modulus = module.params.get("modulus")
    certificate = module.params.get("certificate")
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="pkiKeyRing",
            aci_rn="userext/pkiext/keyring-{0}".format(name),
            module_object=name,
            target_filter=dict(name=name),
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pkiKeyRing",
            class_config=dict(
                name=name,
                descr=description,
                cert=certificate,
                modulus=modulus,
                tp=trustpoint
            ),
        )

        aci.get_diff(aci_class="pkiKeyRing")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
