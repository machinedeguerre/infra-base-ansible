# Infra Base Ansible

How to start using this in your own project:

## 1. Create your directory

```
$ mkdir myansibleproject
$ cd myansibleproject
```

## 2. Add collection dependency

Create your `collections/requirements.yml`:

```
$ mkdir collections
```

And add the file `collections/requirements.yml` with this content:

```
collections:
  - name: git+https://github.com/machinedeguerre/infra-base-ansible.git
    type: git
    version: main
```

Install dependency:

```
$ ansible-galaxy collection install -r collections/requirements.yml
```

## 3. Create infratool file

Create a file called `infratool` with this content:

```
#!/usr/bin/env bash
pushd "$(dirname $0)" >/dev/null
if [ ! -e collections/ansible_collections/infra/base/tools/infratool.sh ]; then
  echo "The infra.base collection is not installed." >&2
  echo "Run: ansible-galaxy collection install -r collections/requirements.yml"
  exit 1
fi
collections/ansible_collections/infra/base/tools/infratool.sh "$@"
popd >/dev/null
```

Also, make it executable:

```
$ chmod a+x infratool
```

## 4. Create ansible configuration

Create file `ansible.cfg` with content:

```
[ssh_connection]
pipelining = True
control_path_dir = ~/.ansible/cp
control_path = %(directory)s/%%h-%%p-%%r
ssh_args = -o ControlMaster=auto -o ControlPersist=30m -o ServerAliveInterval=15 -o ServerAliveCountMax=3

[defaults]
inventory = ./inventory
collections_path = ./collections
roles_path =
vault_identity_list = project@./collections/ansible_collections/infra/base/scripts/vault_pass_gpg.sh
```

## 5. Add your local vars dirs:

```
$ mkdir  -p inventory/group_vars/all
$ mkdir -p inventory/host_vars/myserver # (or whatever)
```

and your `inventory.yml`

## 6. Create a playbooks directory

```
$ mkdir playbooks
```

## 7. Add your gpg key id(s) to `.gpg-id`

Same format as gnu pass.




