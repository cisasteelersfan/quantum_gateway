from setuptools import setup

with open('README.md', 'r') as fh:
    long_description = fh.read()

with open('requirements.txt', 'r') as fh:
    requirements = fh.read().splitlines()

setup(
    name='quantum_gateway',
    version='0.0.5',
    author='Colby Rome',
    author_email='colbyrome@gmail.com',
    description='Query a Quantum Gateway',
    py_modules=['quantum_gateway'],
    install_requires=requirements,
    package_dir={'': 'src'},
    url='https://github.com/cisasteelersfan/quantum_gateway',
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
)
