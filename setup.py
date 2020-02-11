from setuptools import setup, Extension

def readme():
    with open('README.md') as f:
        return f.read()

DESC = "Create and verify common LDAP passwords and hashes"

setup(name='pySSHA',
      version='1.0.0',
      description=DESC,
      long_description=readme(),
      long_description_content_type='text/markdown',
      classifiers=['Development Status :: 5 - Production/Stable',
                  'License :: OSI Approved :: BSD License',
                  'Programming Language :: Python :: 3'],
      url='https://github.com/peppelinux/pySSHA',
      author='Giuseppe De Marco',
      author_email='giuseppe.demarco@unical.it',
      license='BSD',
      scripts=['pySSHA/ssha.py'],
      packages=['pySSHA'],
      #install_requires=[
      #                'pycrypto'
      #            ],
     )
