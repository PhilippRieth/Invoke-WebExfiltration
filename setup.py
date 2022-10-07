#!/usr/bin/env python3

from setuptools import setup, find_packages


setup(name='Invoke-WebExfiltration',
      version='0.1',
      description='Exfiltrate data via PowerShell HTTP(s) POST request (with file gzip compression and AES-256 encryption)',
      author='Philipp Rieth',
      url='https://github.com/PhilippRieth/Invoke-WebExfiltration',
      packages=find_packages(),
      entry_points={
            'console_scripts': [
                  'iwe-server=iwe-server:main'
            ]
      },
      long_description=open('README.md', 'r').read(),
      long_description_content_type='text/markdown',
      # include_package_data=True,
      install_requires=[
            'Flask>=2.2.2',
            'pycryptodome>=3.15.0',
            'requests>=2.28.1',
            'pyopenssl>=22.1.0'
      ],
      python_requires='>=3'
     )