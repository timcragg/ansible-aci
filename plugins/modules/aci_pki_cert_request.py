#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Tim Cragg (@timcragg) <tcragg@cisco.com>
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {"metadata_version": "1.1", "status": ["preview"], "supported_by": "certified"}

DOCUMENTATION = r"""
---
module: aci_pki_cert_request
short_description: Manage PKI Certificate Requests (pki:CertReq)
description:
- Manage PKI Certificate Requests on Cisco ACI fabrics.
options:
  keyring:
    description:
    - The name of the PKI Keyring to create the Certificate Signing Request under.
    type: str
  subj_name:
    description:
    - Subject name of the Certificate Signing Request
    type: str
    aliases: [ subject_name, subject ]
  alt_subj_name:
    description:
    - Comma separated list of Subject Alternate Names (SANs) for the Certificate Signing Request
    type: str
    aliases: [ san, alt_subject_name ]
  country:
    description:
    - Country code for the Certificate Signing Request
    type: str
  email:
    description:
    - email address for the Certificate Signing Request
    type: str
  locality:
    description:
    - Locality value for the Certificate Signing Request
    type: str
  org:
    description:
    - Organization value for the Certificate Signing Request
    type: str
    aliases: [ organization, org_name ]
  org_unit:
    description:
    - Organization Unit value for the Certificate Signing Request
    type: str
    aliases: [ organization_unit ]
  csr_state:
    description:
    - State or province for the Certificate Signing Request
    type: str
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
- name: Add a PKI CSR
  cisco.aci.aci_pki_cert_request:
    host: apic
    username: admin
    password: SomeSecretPassword
    trustpoint: ans_trustpoint
    subj_name: example.com
    state: present
  delegate_to: localhost

- name: Query a PKI CSR
  cisco.aci.aci_pki_cert_request:
    host: apic
    username: admin
    password: SomeSecretPassword
    subj_name: anstest_trustpoint
    state: query
  delegate_to: localhost

- name: Query all PKI CSRs
  cisco.aci.aci_pki_cert_request:
    host: apic
    username: admin
    password: SomeSecretPassword
    state: query
  delegate_to: localhost

- name: Remove a PKI CSR
  cisco.aci.aci_pki_cert_request:
    host: apic
    username: admin
    password: SomeSecretPassword
    subj_name: anstest_trustpoint
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
        subj_name=dict(type="str", aliases=["subject_name", "subject"]),
        alt_subj_name=dict(type="str", aliases=["san", "alt_subject_name"]),
        country=dict(type="str"),
        email=dict(type="str"),
        locality=dict(type="str"),
        org=dict(type="str", aliases=["organization", "org_name"]),
        org_unit=dict(type="str", aliases=["organization_unit"]),
        csr_state=dict(type="str"),
        keyring=dict(type="str"),
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

    subj_name = module.params.get("subj_name")
    alt_subj_name = module.params.get("alt_subj_name")
    country = module.params.get("country")
    email = module.params.get("email")
    locality = module.params.get("locality")
    org = module.params.get("org")
    org_unit = module.params.get("org_unit")
    csr_state = module.params.get("csr_state")
    keyring=dict(type="str"),
    state = module.params.get("state")

    aci = ACIModule(module)
    aci.construct_url(
        root_class=dict(
            aci_class="pkiKeyRing",
            aci_rn="userext/pkiext/keyring-{0}".format(keyring),
            module_object=keyring,
            target_filter=dict{"name": keyring},
        ),
        subclass_1=dict(
            aci_class="pkiCertReq",
            aci_rn="certreq",
            module_object=subj_name,
            target_filter={"subjName": subj_name},
        ),
    )
    aci.get_existing()

    if state == "present":
        aci.payload(
            aci_class="pkiCertReq",
            class_config=dict(
                subjName=subj_name,
                altSubjName=alt_subj_name,
                country=country,
                email=email,
                locality=locality,
                orgName=org,
                orgUnitName=org_unit
            ),
        )

        aci.get_diff(aci_class="pkiKeyRing")

        aci.post_config()

    elif state == "absent":
        aci.delete_config()

    aci.exit_json()


if __name__ == "__main__":
    main()
