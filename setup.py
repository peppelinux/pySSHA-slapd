from setuptools import setup

def readme():
    with open('README.md') as f:
        return f.read()

setup(name='pySSHA',
      version='0.6',
      description="Create and verify LDAP password and hash",
      long_description=readme(),
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
