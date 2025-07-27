from setuptools import setup, find_packages

setup(
    name='django-api-monitor',
    version='0.1.0',
    packages=find_packages(),
    include_package_data=True,
    install_requires=[
        'Django>=3.2',
        'psutil',
    ],
    description='Reusable Django app for monitoring API usage and security.',
    author='anirudh_mk',
    license='MIT',
    classifiers=[
        'Framework :: Django',
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
    ],
)