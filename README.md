# spe-FirewallRuleGenerator
Generates firewall rules from a policy file, and can also validate a data file against a JSON Schema held in a policy file.

Rule generation: when the policy file holds a `rules` list (or a single `rule` mapping), the tool emits one iptables style line per rule, in order, carrying the rule's protocol (default tcp), source (default 0.0.0.0/0, read from `source` or `src`), port when the rule names one (`port` or `destination_port`), and target: ACCEPT for allow, accept, or permit, and DROP for deny, drop, block, or reject. The action may also be given as `effect`. A rule with no recognized action is a validation error at non-zero exit. The protocol must be a single alphanumeric token, the source must be an IP address or CIDR range, and a port must be an integer from 0 to 65535: a rule failing any of these is a validation error at non-zero exit, so a field value cannot split or alter the generated line. An empty rules list generates nothing and exits non-zero. In this mode the data file argument is not used. No template library is used; lines are built directly in the code. Generated lines are printed only; nothing is applied to any firewall.

Schema validation: when the policy file holds a `schema` key instead, the tool validates the data file against that JSON Schema, as it did before. A conforming data file exits 0. A violation prints the does not conform verdict and exits 1.

## Install
`git clone https://github.com/ShadowGuard-AI/spe-firewallrulegenerator`

## Usage
`python3 main.py POLICY_FILE [DATA_FILE] [--log_level LEVEL]`

Policy file example for generation:
```yaml
rules:
  - action: allow
    protocol: tcp
    port: 443
    source: 10.0.0.0/8
  - action: deny
    protocol: udp
    port: 53
    source: 0.0.0.0/0
```

## Parameters
- `policy_file`: Path to the YAML/JSON policy file (a `rules` list, or a `schema` key).
- `data_file`: Path to the YAML/JSON data file to validate in schema mode.
- `-h`: Show help message and exit
- `--log_level`: Set the logging level. Defaults to INFO.

## License
MIT License. See LICENSE.
