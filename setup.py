from setuptools import setup

with open("readme.md", "r") as fh:
    long_description = fh.read()

setup(
    name='quantum_gateway',
    version='0.1.0',
    description='Query a Quantum Gateway',
    py_modules=['quantum_gateway'],
    package_dir={'': 'src'},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    long_description=long_description,
    long_description_content_type="text/markdown",
)
