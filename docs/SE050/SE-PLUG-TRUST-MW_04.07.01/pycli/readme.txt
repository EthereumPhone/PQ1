
Windows
====================

Ensure 32 bit Python 3.8 or later is installed.

Run following commands::

    pip3 install virtualenv
    python -m virtualenv venv
    call venv\Scripts\activate.bat
    pip install -r requirements.txt
    cd src
    pip install --editable .


OS X
====================

Ensure Python 3  is installed::

    sudo apt install python3-virtualenv
    virtualenv venv
    source venv/bin/activate
    pip3 install -r requirements.txt
    cd src
    pip3 install --editable .

Alpine Linux
=====================================

    # setup.py -> py-setuptools
    # cryptography -> libffi-dev -> python2-dev
    # cryptography -> openssl-dev
    RUN apk add py-setuptools libffi-dev python2-dev openssl-dev
    RUN mkdir /sources/simw-top_build
    RUN cd /sources/simw-top_build \
        && cmake ../simw-top \
            -DWithHost_PCLinux64=ON \
            -DWithSMCOM_JRCP=ON \
            -DWithSMCOM_VCOM=OFF \
        && make sssapisw -j

    RUN cd /sources/simw-top/pycli/src \
        && python3 setup.py develop

iMX Linux (Created with Yocto)
======================================

Use the procedure described in simw-top/doc/index.html
(Section 9. Appendix => 9.5.1. Setup i.MX 8MQuad - MCIMX8M-EVK)
to create an SD card containing the Linux image.

Run the following commands::

  cd src
  python3 setup.py develop
