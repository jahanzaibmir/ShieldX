import logging
import logging.config
import yaml
import os

CONFIG_PATH = r"C:\SheildX\config\logging.yaml"

def setup_logging():
    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError("Logging config not found")

    with open(CONFIG_PATH, "r") as f:
        config = yaml.safe_load(f)

    logging.config.dictConfig(config)

def get_logger(name: str):
    return logging.getLogger(name)
