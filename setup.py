from setuptools import setup, find_packages

setup(
    name="agent-security-sandbox",
    version="1.0.0",
    description="AST Security Inspector and Runtime Sanitizer for Autonomous AI Agents",
    author="Roman Pokushko",
    author_email="pokusko.roman@gmail.com",
    packages=find_packages(),
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
)
