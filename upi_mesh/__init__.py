import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s.%(msecs)03d [%(threadName)s] %(levelname)-5s %(name)s - %(message)s",
    datefmt="%H:%M:%S",
)
