#!/usr/bin/env python
"""esp_flasher setup script."""
import os

from setuptools import setup, find_packages

from esp_flasher import const

PROJECT_NAME = 'ESP_Flasher'
PROJECT_PACKAGE_NAME = 'esp_flasher'
PROJECT_LICENSE = 'MIT'
PROJECT_AUTHOR = 'Jason2866'
PROJECT_COPYRIGHT = '2023, Jason2866'
PROJECT_URL = 'https://github.com/Jason2866/ESP_Flasher'
PROJECT_EMAIL = 'obermeier.johann@googlemail.com'

PROJECT_GITHUB_USERNAME = 'Jason2866'
PROJECT_GITHUB_REPOSITORY = 'ESP_Flasher'

PYPI_URL = 'https://pypi.python.org/pypi/{}'.format(PROJECT_PACKAGE_NAME)
GITHUB_PATH = '{}/{}'.format(PROJECT_GITHUB_USERNAME, PROJECT_GITHUB_REPOSITORY)
GITHUB_URL = 'https://github.com/{}'.format(GITHUB_PATH)

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, 'requirements.txt')) as requirements_txt:
    REQUIRES = requirements_txt.read().splitlines()

with open(os.path.join(here, 'README.md')) as readme:
    LONG_DESCRIPTION = readme.read()


setup(
    name=PROJECT_PACKAGE_NAME,
    version=const.__version__,
    license=PROJECT_LICENSE,
    url=GITHUB_URL,
    author=PROJECT_AUTHOR,
    author_email=PROJECT_EMAIL,
    description="ESP8266/ESP32 Tasmota firmware flasher for ESP",
    include_package_data=True,
    zip_safe=False,
    platforms='any',
    test_suite='tests',
    python_requires='>=3.8,<4.0',
    install_requires=REQUIRES,
    long_description=LONG_DESCRIPTION,
    long_description_content_type='text/markdown',
    keywords=['home', 'automation'],
    entry_points={
        'console_scripts': [
            'esp_flasher = esp_flasher.__main__:main'
        ]
    },
    packages=find_packages(include="esprelease.*")
)
