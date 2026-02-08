from shieldx_logging.logger import setup_logging, get_logger

def main():
    setup_logging()
    logger = get_logger("ShieldX")
    logger.info("ShieldX started successfully")
    logger.warning("This is a warning test")
    logger.error("This is an error test")

if __name__ == "__main__":
    main()
