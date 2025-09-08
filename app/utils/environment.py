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