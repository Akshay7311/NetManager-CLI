from setuptools import setup, find_packages

setup(
    name='netmanager',
    version='0.1.0',
    description='Cross-platform network management CLI tool',
    author='Your Name',
    packages=find_packages(),
    install_requires=[
        'python-nmap',
        'scapy',
        'prettytable',
    ],
    entry_points={
        'console_scripts': [
            'netmanager=netmanager.__main__:main',
        ],
    },
) 