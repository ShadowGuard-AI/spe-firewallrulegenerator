# spe-FirewallRuleGenerator
A simple CLI that takes a description of desired network access (e.g., 'Allow web traffic to server X') and generates firewall rules for iptables or ufw based on predefined templates, using Jinja2 for template rendering. - Focused on Defines and enforces security policies (e.g., password complexity, file access permissions, allowed network connections) using YAML/JSON configuration files. Can be used to validate system configurations, user settings, or application behavior against a defined policy. Generates alerts for policy violations.

## Install
`git clone https://github.com/ShadowStrikeHQ/spe-firewallrulegenerator`

## Usage
`./spe-firewallrulegenerator [params]`

## Parameters
- `-h`: Show help message and exit
- `--log_level`: No description provided

## License
Copyright (c) ShadowStrikeHQ
