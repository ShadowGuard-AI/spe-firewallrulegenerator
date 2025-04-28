import argparse
import logging
import sys
import yaml
import json
from jsonschema import validate, ValidationError

# Configure logging
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)


def setup_argparse():
    """
    Sets up the argument parser for the CLI.
    """
    parser = argparse.ArgumentParser(
        description="Security Policy Enforcer. Validates system configurations against a defined policy."
    )
    parser.add_argument(
        "policy_file",
        help="Path to the YAML/JSON policy file.",
        type=str,
    )
    parser.add_argument(
        "data_file",
        help="Path to the YAML/JSON data file containing system configuration, user settings, or application behavior.",
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


def main():
    """
    Main function to load policy and data, validate the data against the policy,
    and report any violations.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    # Set log level
    logging.getLogger().setLevel(args.log_level)

    try:
        policy_data = load_data(args.policy_file)
        data_to_validate = load_data(args.data_file)

        if "schema" not in policy_data:
            logging.error("Policy file must contain a 'schema' key.")
            sys.exit(1)

        schema = policy_data["schema"]
        is_valid = validate_data(data_to_validate, schema)

        if is_valid:
            logging.info("Data is valid according to the policy.")
            print("Data is valid according to the policy.")
        else:
            logging.warning("Data does not conform to the defined policy.")
            print("Data does not conform to the defined policy.")
            # Example: Provide more detailed output based on violations
            # This would require more complex logic based on the schema and validation errors.

    except Exception as e:
        logging.critical(f"An unexpected error occurred: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()