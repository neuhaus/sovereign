# Contributing to Sovereign

## Intellectual property

Make sure you agree with the license (GPLv3). See [LICENSE.md](./LICENSE.md) for details.

Code on the `trixie-wip` branch targets Debian 13 "Trixie" and Debian Testing. Other distributions are not supported.

The current state of the rebuild, decisions that go beyond the modernization plan and known pitfalls are tracked in [docs/STATUS.md](docs/STATUS.md).

## Development environment

Tests run with [Molecule](https://ansible.readthedocs.io/projects/molecule/) in [incus](https://linuxcontainers.org/incus/) system containers. Each scenario starts three containers on its own bridge: `mail` (the system under test), `dns` (authoritative mock DNS for `sovereign.test`) and `pebble` (a local ACME server).

```sh
pip install -r test-requirements.txt
ansible-galaxy collection install -r requirements.yml

yamllint --strict .
ansible-lint
molecule list   # loads all scenarios, catches errors in molecule.yml

molecule test --scenario-name trixie
molecule test --scenario-name testing
```

Your user needs access to incus (membership in `incus-admin`). During development, `molecule converge` and `molecule verify` keep the containers running between iterations; `molecule destroy` removes them.

CI runs the same steps on GitHub Actions (`.github/workflows/ci.yml`). When a Molecule run fails there, the job prints the failed units with their journals and the current fail2ban bans of every instance.

Test accounts and their passwords are defined in `.config/molecule/config.yml`. Molecule expands environment variables in that file, so every dollar sign (for example in password hashes) must be written as `$$`.

## Coding conventions

- Use fully qualified collection names (`ansible.builtin.apt`, not `apt`).
- New code must pass `ansible-lint` (production profile) and `yamllint --strict`. Legacy paths are excluded in `.ansible-lint` and `.yamllint` until they are removed or rewritten.
- Use the `sovereign_debian_track` fact (`trixie` or `testing`, set by the `preflight` role) for release-specific logic instead of hard-coding codenames.
- Every handler that restarts a service validates the configuration first, for example `postfix check`, `doveconf -n -c /etc/dovecot/dovecot.conf`, `nginx -t`, `nft -c -f /etc/nftables.conf`, `unbound-checkconf` or `rspamadm configtest`. Prefer the `validate` parameter of `template`/`copy` where the tool supports checking a single file.
- Handlers run in the order they are defined; give the check and the restart the same `listen` topic and define the check first.
- Role variables carry the role name as prefix (ansible-lint `var-naming`). Inventory variables shared by several roles (`mail_domains`, `mail_mailboxes`, `mail_aliases`, `monitoring_sources`) are mapped to prefixed role defaults, e.g. `maildb_domains: "{{ mail_domains | default([]) }}"`.
- Pass the configuration file explicitly to Dovecot 2.4 tools (`sievec -c`, `doveconf -c`): without it they use the configuration of the running Dovecot, which may be outdated during a run.
- A role is done when its tests in `molecule/resources/tests/` are green in CI.

## Module design principles

Sovereign is an Ansible playbook that uses the modules in this repository to configure a server. Modules should conform to the following design principles.

### Naming

Modules should be named after the software they add (as opposed to the functionality they provide), for example `dovecot`, `rspamd` or `unbound`, so that it is possible to provide alternatives for functionality. Roles that configure a mechanism rather than one package are named after it (`maildb`, `systemd_timers`).

### Making decisions

A module exists to make decisions about how a service should be installed and configured. Make these decisions and minimize or eliminate configuration options exposed to the user. When in doubt, make a decision, and if the community feedback is vocal enough, only then expose an option.

### Idempotency

A module must be idempotent. If it's run once or many times, the result should be the same. This means that in some cases the user will be left with post-installation finalization work to do. Post-install finalization should be reduced or eliminated if possible, but not at the cost of idempotency.

### Databases

Sovereign runs no database server. Services that need a database use SQLite, as long as the data and write load stay within SQLite's design limits (the mail database has a single writer, Ansible). Give each service its own database file. Readers that must not write (Postfix, Dovecot) open SQLite databases read-only, and databases stay in rollback-journal mode (`journal_mode = DELETE`): WAL needs write access for every reader.

### Registrations

A module should configure the server in a way that minimizes the data posted to other services. This includes names, email addresses, and other personally-identifable information. 

### Upgrades

A module's design should anticipate upgrades to the services it provides. Configuration files that work for the current version of the service may become out of date on future versions of the service and lead to difficult-to-find bugs. This also introduces work for maintaining the module.  Whenever possible, design the module to use the service to handle initial configuration and upgrades.

### Performance

A module should be designed and implemented to run as quickly as possible in order to minimize the time to run an entire playbook or even the role itself. A small performance penalty here and a small penalty there eventually adds to a very slow deployment system. Performance is important.

### Tests

A module must have tests in `molecule/resources/tests/` (pytest-testinfra) that check the behaviour, not just the configuration: a mail is delivered, a login is refused, a port is closed. Some rules:

- Test from another instance where the server treats local clients differently (Dovecot allows plaintext logins from its own address). `mailclient.py` runs SMTP/IMAP/TLS clients on the `dns` instance.
- Tests that deliberately cause failures (wrong passwords, refused TLS versions) run from `dns`, which fail2ban ignores in Molecule; `pebble` stays bannable for the fail2ban test.
- `host.ansible.get_variables()` returns inventory values untemplated; use the `ansible_var` fixture for values containing Jinja.
- Make checks fail loudly: a comparison of two empty results passes silently.

### Design document

A module should have a design description explaining the approach to implementing a service and what tradeoffs were made when choosing the design that was implemented. Do not leave this for comments in a pull request as we want this close to the code for the sake of future maintainers.

The design description should be succinct and to the point. Assume the reader is familiar with Sovereign but not your module. As a rule of thumb, 500-1000 words is about the right length for a module design description.

## Design checklist

Consider the following checklist when reviewing a module's design.

- Does the role create data on the server that is impossible or difficult to reproduce, e.g., private keys? If so, make sure it is included in backups.
- Does the role need a certificate for a new host name? If so, add it to `certbot_domains`; the certbot role reissues the certificate with the same key.
- Does the role add an nginx site? If so, has somebody knowledgeable in nginx configuration and security reviewed it?
- Does the role open a port? If so, update the nftables role and the firewall tests.
- Does README.md need to be updated based on new or changed finalization instructions?

## Submitting pull requests

Verify that your changes pass `yamllint --strict .`, `ansible-lint` and both Molecule scenarios before submitting a pull request.

Use good commit practices to document your changes. Don't assume the developer reviewing your commits has access to GitHub. The developer could be a future maintainer in a different environment. Similarly, as you address feedback on the pull request, do not assume the reviewer has access to GitHub.

Code must work on Debian 13 and on Debian Testing; CI tests both. Mention in the pull request if you also tested on a real server.
