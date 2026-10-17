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
    version: <commit-sha>
```

To avoid supply chain-attacks, always pin `version:` to a specific commit SHA.

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
ssh_args = -o ControlMaster=auto -o ControlPersist=30m -o ServerAliveInterval=15 -o ServerAliveCountMax=3 -o UserKnownHostsFile=./.known_hosts

[defaults]
inventory = ./inventory
collections_path = ./collections
roles_path =
host_key_checking = True
vault_identity_list = project@./collections/ansible_collections/infra/base/scripts/vault_pass_gpg.sh
```

Host keys are verified against `./.known_hosts`, which `./infratool play`
derives from the vaulted host keys (`generate_sshd_hostkeys`) — so run
playbooks through `./infratool play` and run them from the project root.
Add `.known_hosts` to your `.gitignore`.

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

## 8. Create an ansible vault password (encrypted by gpg)

Your vault password is stored in `.vault-pass.gpg`,
which is encrypted to the gpg keys in `.gpg-id`.

To create it:

```
$ ./infratool generate_vault_password
```

## 9. Voilà!

Start using the collection roles!

## Nebula CA journal

Info about every certificate signing (host rotations and external bundles)
is appended to `logs/nebula-cert-log.csv`. Commit it, so you have the
fingerprints to put in `nebula_blocklist` when a cert must be revoked.

## Infratool commands

Run `./infratool` without arguments to list available commands.

### play `[--tofu]` `<ansible-playbook arguments...>`

Runs `ansible-playbook` with strict SSH host key checking. Before running, it
regenerates `./.known_hosts` from the vaulted host keys
(`inventory/host_vars/*/hostkeys.vault.yml`), listing every address a host is
reached on (`ansible_host` + `nebula_ip`). The file is cached: it is only
regenerated when something under `inventory/` is newer than it or its line
count no longer matches its header.

```
./infratool play playbooks/main.yml -l myserver
```

`--tofu` disables host key checking for that single run. Use it only to
bootstrap a freshly installed host, which still presents its
installer-generated host keys; the sshd role replaces them with the vaulted
ones on the first `main.yml` run, after which strict checking works:

```
./infratool play --tofu playbooks/bootstrap.yml -l mynewserver -e ansible_user=user
```

### generate_vault_password

Generates a random vault password and encrypts it with GPG to `.vault-pass.gpg`. The GPG recipients are read from `.gpg-id` in the project root.

```
./infratool generate_vault_password
```

### generate_root_password `<host>`

Generates a random root password for a host and stores it vault-encrypted in `inventory/host_vars/<host>/root_password.vault.yml`.

```
./infratool generate_root_password myserver
```

### get_root_password `<host>`

Decrypts and prints the root password for a host.

```
./infratool get_root_password myserver
```

### generate_wireguard_keys `<host>`

Generates a WireGuard private key for a host and stores it vault-encrypted in `inventory/host_vars/<host>/wireguard.vault.yml`. Prints the public key to stdout.

```
./infratool generate_wireguard_keys myserver
```

### get_wireguard_public_key `<host>`

Decrypts the WireGuard private key for a host and calculates and prints its public key.

```
./infratool get_wireguard_public_key myserver
```

### generate_sshd_hostkeys `<host>`

Generates SSH host keys (ed25519, RSA, ECDSA) for a host and stores them vault-encrypted in `inventory/host_vars/<host>/hostkeys.vault.yml`.

```
./infratool generate_sshd_hostkeys myserver
```

### generate_sshtunnel_keys `<host>`

Generates an ed25519 keypair for SSH reverse tunnels and stores the private key vault-encrypted in `inventory/host_vars/<host>/sshtunnel.vault.yml`. Prints the public key to stdout.

```
./infratool generate_sshtunnel_keys myserver
```

### generate_proxmox_token_secret `<host>`

Generates a random Proxmox API token secret for a host and stores it vault-encrypted in `inventory/host_vars/<host>/proxmox_token_secret.vault.yml`.

```
./infratool generate_proxmox_token_secret myserver
```

### generate_wildcard_cert `<domain>`

Generates a Let's Encrypt wildcard certificate (for `*.<domain>` and `<domain>`) via the manual DNS-01 challenge. `certbot` prints the `_acme-challenge` TXT record(s) for you to add to DNS and waits for you to confirm propagation. The resulting certificate and private key are stored vault-encrypted in `inventory/group_vars/all/wildcard_cert.<domain>.vault.yml`.

Skipped if an existing certificate in that vault file was issued less than 7 days ago (checked against the certificate's own `notBefore` field, not the file mtime).

Requires `certbot` to be available in the dev shell.

```
./infratool generate_wildcard_cert example.org
```

### import_vault `<source_file>` `<destination_path>`

Imports a vault file from another project, decrypting it with the source project's vault password and re-encrypting it with this project's vault password. The source project root is detected automatically by walking up the directory tree from the source file.

```
./infratool import_vault ../other-project/inventory/host_vars/myserver/vault.yml inventory/host_vars/myserver/vault.yml
```

