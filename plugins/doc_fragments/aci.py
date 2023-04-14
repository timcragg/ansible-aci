# -*- coding: utf-8 -*-

# Copyright: (c) 2017, Dag Wieers (@dagwieers) <dag@wieers.com>
# Copyright: (c) 2017, Swetha Chunduri (@schunduri)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  host:
    description:
    - IP Address or hostname of APIC resolvable by Ansible control host.
    - If the value is not specified in the task, the value of environment variable C(ACI_HOST) will be used instead.
    type: str
    required: true
    aliases: [ hostname ]
  port:
    description:
    - Port number to be used for REST connection.
    - The default value depends on parameter C(use_ssl).
    - If the value is not specified in the task, the value of environment variable C(ACI_PORT) will be used instead.
    type: int
  username:
    description:
    - The username to use for authentication.
    - If the value is not specified in the task, the value of environment variables C(ACI_USERNAME) or C(ANSIBLE_NET_USERNAME) will be used instead.
    type: str
    default: admin
    aliases: [ user ]
  password:
    description:
    - The password to use for authentication.
    - This option is mutual exclusive with C(private_key). If C(private_key) is provided too, it will be used instead.
    - If the value is not specified in the task, the value of environment variables C(ACI_PASSWORD) or C(ANSIBLE_NET_PASSWORD) will be used instead.
    type: str
  private_key:
    description:
    - Either a PEM-formatted private key file or the private key content used for signature-based authentication.
    - This value also influences the default C(certificate_name) that is used.
    - This option is mutual exclusive with C(password). If C(password) is provided too, it will be ignored.
    - If the value is not specified in the task, the value of environment variable C(ACI_PRIVATE_KEY) or C(ANSIBLE_NET_SSH_KEYFILE) will be used instead.
    type: str
    aliases: [ cert_key ]
  certificate_name:
    description:
    - The X.509 certificate name attached to the APIC AAA user used for signature-based authentication.
    - If a C(private_key) filename was provided, this defaults to the C(private_key) basename, without extension.
    - If PEM-formatted content was provided for C(private_key), this defaults to the C(username) value.
    - If the value is not specified in the task, the value of environment variable C(ACI_CERTIFICATE_NAME) will be used instead.
    type: str
    aliases: [ cert_name ]
  output_level:
    description:
    - Influence the output of this ACI module.
    - C(normal) means the standard output, incl. C(current) dict
    - C(info) adds informational output, incl. C(previous), C(proposed) and C(sent) dicts
    - C(debug) adds debugging output, incl. C(filter_string), C(method), C(response), C(status) and C(url) information
    - If the value is not specified in the task, the value of environment variable C(ACI_OUTPUT_LEVEL) will be used instead.
    type: str
    choices: [ debug, info, normal ]
    default: normal
  timeout:
    description:
    - The socket level timeout in seconds.
    - If the value is not specified in the task, the value of environment variable C(ACI_TIMEOUT) will be used instead.
    type: int
    default: 30
  use_proxy:
    description:
    - If C(false), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    - If the value is not specified in the task, the value of environment variable C(ACI_USE_PROXY) will be used instead.
    type: bool
    default: true
  use_ssl:
    description:
    - If C(false), an HTTP connection will be used instead of the default HTTPS connection.
    - If the value is not specified in the task, the value of environment variable C(ACI_USE_SSL) will be used instead.
    type: bool
    default: true
  validate_certs:
    description:
    - If C(false), SSL certificates will not be validated.
    - This should only set to C(false) when used on personally controlled sites using self-signed certificates.
    - If the value is not specified in the task, the value of environment variable C(ACI_VALIDATE_CERTS) will be used instead.
    type: bool
    default: true
  output_path:
    description:
    - Path to a file that will be used to dump the ACI JSON configuration objects generated by the module.
    - If the value is not specified in the task, the value of environment variable C(ACI_OUTPUT_PATH) will be used instead.
    type: str
seealso:
- ref: aci_guide
  description: Detailed information on how to manage your ACI infrastructure using Ansible.
- ref: aci_dev_guide
  description: Detailed guide on how to write your own Cisco ACI modules to contribute.
"""
