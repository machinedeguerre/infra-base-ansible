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
if [ ! -e collections/ansible_collections/infra/base/tools/tool.sh ]; then
  echo "The infra.base collection is not installed." >&2
  echo "Run: ansible-galaxy collection install -r collections/requirements.yml -p $ANSIBLE_COLLECTIONS_PATH" >&2
  exit 1
fi
collections/ansible_collections/infra/base/tools/infratool.sh "$@"
popd >/dev/null
```

Also, make it executable:

```
$ chmod a+x infratool
```


