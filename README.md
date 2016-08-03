# OpenConext-eidas

OpenConext-eidas is a SAML Proxy acting as a Identity Provider in the OpenConext SAML Federation and as a
ServiceProvider for eIDAS

## [Getting started](#getting-started)

### [System Requirements](#system-requirements)

- Java 8
- Maven 3

## [Deployment](#deployment)

### Ansible

A complete VM can be deployed with ansible. This project uses the Ansible "environment" setup as described in
https://github.com/pmeulen/ansible-tools. Secrets are encrypted using keyczar (see [environment.conf](ansible/environments/template/environment.conf))

To prepare for a deploy you must first create a new "environment" and customise it:

1. Install the dependencies for using [ansible-tools](https://github.com/pmeulen/ansible-tools)

   - ansible. Use e.g. `pip install ansible`
   - python-keyczar. Use e.g. `pip install python-keyczar`

2. Create a new environment:
  `cd ansible`
  `./scripts/create_new_environment.sh <environment dir>`

3. Update the inventory and groups_vars in the generated environment to match your setup

4. Deploy using ansible:
   `ansible-playbook eidas.yml -i <environment dir>/inventory`
