from setuptools import setup, find_packages

setup(
    name='firewall_project',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'scapy==2.4.5',
        'flask==2.0.3',
    ],
    entry_points={
        'console_scripts': [
            'run-firewall=scripts.run_firewall:main',
        ],
    },
)
