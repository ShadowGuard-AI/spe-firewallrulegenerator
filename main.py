import argparse
import logging
import sys
import yaml
import json
from jsonschema import validate, ValidationError
import ipaddress
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(
        description="Generates iptables style firewall rules from a policy file holding a rules list, and validates a data file against a JSON Schema held in a policy file."
    )
    parser.add_argument(
        "policy_file",
        help="Path to the YAML/JSON policy file.",
        type=str,
    )
    parser.add_argument(
        "data_file",
        nargs="?",
        default=None,
        help="Path to the YAML/JSON data file to validate. Required in schema validation mode; not used when the policy file holds a rules list to generate from.",
        type=str,
    )
    parser.add_argument(
        "--log_level",
        help="Set the logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL).",
        default="INFO",
        type=str,
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
    )
    return parser


def load_data(file_path):
    """
    Loads data from a YAML or JSON file.

    Args:
        file_path (str): Path to the file.

    Returns:
        dict: The loaded data as a dictionary.
    """
    try:
        with open(file_path, "r") as f:
            if file_path.endswith((".yaml", ".yml")):
                data = yaml.safe_load(f)
            elif file_path.endswith(".json"):
                data = json.load(f)
            else:
                raise ValueError("Unsupported file format. Use YAML or JSON.")
        return data
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        raise
    except yaml.YAMLError as e:
        logging.error(f"Error parsing YAML file: {e}")
        raise
    except json.JSONDecodeError as e:
        logging.error(f"Error parsing JSON file: {e}")
        raise
    except Exception as e:
        logging.error(f"Error loading data: {e}")
        raise


def validate_data(data, schema):
    """
    Validates data against a JSON schema.

    Args:
        data (dict): The data to validate.
        schema (dict): The JSON schema.

    Returns:
        bool: True if the data is valid, False otherwise.
    """
    try:
        validate(instance=data, schema=schema)
        return True
    except ValidationError as e:
        logging.error(f"Validation error: {e}")
        return False
    except Exception as e:
        logging.error(f"Unexpected error during validation: {e}")
        return False


def generate_firewall_rules(policy_data):
    """Emit one iptables style line per policy rule, or None if no rules list."""
    rules = None
    if isinstance(policy_data, dict):
        if isinstance(policy_data.get("rules"), list):
            rules = policy_data["rules"]
        elif isinstance(policy_data.get("rule"), dict):
            rules = [policy_data["rule"]]
    if rules is None:
        return None
    lines = []
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            raise ValueError(f"Rule {i} is not a mapping.")
        action_raw = str(rule.get("action", rule.get("effect", ""))).strip().lower()
        if action_raw in ("allow", "accept", "permit"):
            target = "ACCEPT"
        elif action_raw in ("deny", "drop", "block", "reject"):
            target = "DROP"
        else:
            raise ValueError(f"Rule {i} has no recognized action (allow or deny).")
        protocol = str(rule.get("protocol", "tcp")).strip().lower()
        if not re.fullmatch(r"[a-z0-9]+", protocol):
            raise ValueError(f"Rule {i} has an invalid protocol: {protocol!r}.")
        port = rule.get("port", rule.get("destination_port"))
        source = str(rule.get("source", rule.get("src", "0.0.0.0/0"))).strip()
        try:
            ipaddress.ip_network(source, strict=False)
        except ValueError:
            raise ValueError(f"Rule {i} has an invalid source (expected an IP address or CIDR range): {source!r}.")
        line = f"iptables -A INPUT -p {protocol} -s {source}"
        if port is not None:
            if isinstance(port, bool):
                raise ValueError(f"Rule {i} has an invalid port: {port!r}.")
            try:
                port_num = int(port)
            except (TypeError, ValueError):
                raise ValueError(f"Rule {i} has an invalid port: {port!r}.")
            if str(port).strip() not in (str(port_num), f"+{port_num}") and not isinstance(port, int):
                raise ValueError(f"Rule {i} has an invalid port: {port!r}.")
            if not 0 <= port_num <= 65535:
                raise ValueError(f"Rule {i} port is out of range (0 to 65535): {port_num}.")
            line += f" --dport {port_num}"
        line += f" -j {target}"
        lines.append(line)
    return lines



def main():
    parser = setup_argparse()
    args = parser.parse_args()
    logging.getLogger().setLevel(args.log_level)
    try:
        policy_data = load_data(args.policy_file)
        if not isinstance(policy_data, dict) or not policy_data:
            logging.error("Policy file is empty: nothing was generated or validated.")
            sys.exit(2)
        rules_lines = generate_firewall_rules(policy_data)
        if rules_lines is not None:
            if not rules_lines:
                logging.error("Policy rules list is empty: no firewall rules generated.")
                sys.exit(2)
            for line in rules_lines:
                print(line)
            return
        if "schema" not in policy_data:
            logging.error("Policy file must contain a 'schema' key or a 'rules' list.")
            sys.exit(1)
        if not args.data_file:
            logging.error("A data file is required in schema validation mode.")
            sys.exit(2)
        data_to_validate = load_data(args.data_file)
        schema = policy_data["schema"]
        is_valid = validate_data(data_to_validate, schema)
        if is_valid:
            logging.info("Data is valid according to the policy.")
            print("Data is valid according to the policy.")
        else:
            logging.warning("Data does not conform to the defined policy.")
            print("Data does not conform to the defined policy.")
            sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()