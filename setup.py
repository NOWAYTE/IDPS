from setuptools import setup, find_packages

setup(
    name="idps",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'mininet',
        'scapy',
        'numpy',
        'pandas',
        'scikit-learn',
        'joblib',
        'cryptography',
        'psutil',
        'python-dotenv'
    ],
    entry_points={
        'console_scripts': [
            'idps-simulate=idps.simulations.mininet_iot:main',
        ],
    },
)