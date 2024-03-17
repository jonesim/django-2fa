import setuptools

with open("readme.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="django-modal-2fa",
    version="0.0.3",
    author="Ian Jones",
    description="Django app to implement two factor authentication with bootstrap modals",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/jonesim/django-2fa",
    include_package_data = True,
    packages=['modal_2fa'],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=['django-nested-modals', 'qrcode', 'django-otp', 'webauthn>=2.0.0'],
)
