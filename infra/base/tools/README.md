# tools

Scripts in this directory are supposed to run in the scope of the project using this collection.

## Entrypoint for those tools

In the root of your ansible project, create this executable `infratool` file:

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