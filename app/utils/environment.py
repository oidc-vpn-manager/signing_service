import os

def loadConfigValueFromFileOrEnvironment(key: str, default_value: str = '') -> str:
    """
    Load configuration values from a file or environment variable.
    This function reads the entire file content and strips leading/trailing whitespace.
    """
    VALUE_FILE = os.environ.get(f'{key}_FILE')
    if VALUE_FILE:
        if not os.path.exists(VALUE_FILE) or not os.path.isfile(VALUE_FILE):
            raise FileNotFoundError(f'{key}_FILE is set but the path does not exist or is not a file.')

        with open(VALUE_FILE, 'r') as file:
            file_content = file.read().strip()

        if file_content:
            return file_content

    return os.environ.get(key, default_value)


def loadBoolConfigValue(key: str, default: str, prefer: bool = False):
    """
    Load a boolean configuration value from an environment variable.

    Args:
        key: Environment variable name.
        default: Default string value if the environment variable is not set.
        prefer: If True, returns True only for explicit true values.
                If False (default), returns False only for explicit false values.

    Returns:
        bool: The parsed boolean value.
    """
    false_strings = ['false', 'no', 'off', '0']
    true_strings = ['true', 'yes', 'on', '1']
    if prefer:
        return False if not str(os.environ.get(key, default)).lower() in true_strings else True
    else:
        return True if not str(os.environ.get(key, default)).lower() in false_strings else False