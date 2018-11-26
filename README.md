
# Synopsis
Ansible templates which can be used to automate various processes.

# Current Possibilities

- Install 12cR2 software binaries
- Install 12cR1 software binaries
- Install 11gR2 software binaries

- Patch 12cR2 single instance database
- Patch 12cR1 single instance database
- Patch 11gR2 single instance database

# Code Example

- Install oracle software binaries
```
ansible-playbook orasw-install.yml -u oracle --ask-pass --ask-become-pass
```

- Create oracle single instance database
```
ansible-playbook oradb-create.yml -u oracle --ask-pass
```

- Install oracle software binaries and create database
```
ansible-playbook combo_sw_db.yml -u oracle --ask-pass --ask-become-pass
```

# Author

- Ivica Arsov
