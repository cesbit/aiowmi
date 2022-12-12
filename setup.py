"""setup.py
locan installation: pip install -e .

python setup.py sdist
twine upload --repository pypitest dist/aiowmi-x.x.x.tar.gz
twine upload --repository pypi dist/aiowmi-x.x.x.tar.gz
"""
from setuptools import setup, find_packages
from aiowmi import __version__ as version
from setuptools import setup, find_packages

try:
    with open('README.md', 'r') as f:
        long_description = f.read()
except IOError:
    long_description = ''

setup(
    name='aiowmi',
    packages=find_packages(),
    version=version,
    description='Python WMI Queries',
    long_description=long_description,
    long_description_content_type='text/markdown',
    author='Jeroen van der Heijden',
    author_email='jeroen@cesbit.com',
    url='https://github.com/cesbit/aiowmi',
    download_url=(
        'https://github.com/cesbit/'
        'aiowmi/tarball/v{}'.format(version)),
    install_requires=[
        'pycryptodome>=3.14.0'
    ],
    keywords=['WMI', 'Monitoring'],
    classifiers=[
        'Intended Audience :: Developers',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3 :: Only',
        'Topic :: Software Development :: Libraries :: Python Modules',
        'Topic :: Text Processing :: Linguistic'
    ],
)
