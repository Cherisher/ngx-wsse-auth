# ngx-wsse-auth
WSSE Authentication for Nginx

Dependencies
============
* Sources for Nginx_ 1.0.x, and its dependencies.


Building
========

1. Unpack the Nginx_ sources::

    $ tar zxvf nginx-1.0.x.tar.gz

2. Unpack the sources for the wsse module::

    $ tar xzvf nginx-http-auth-wsse-xxxxxxx.tar.gz

3. Change to the directory which contains the Nginx_ sources, run the
   configuration script with the desired options and be sure to put an
   ``--add-module`` flag pointing to the directory which contains the source
   of the wsse module::

    $ cd nginx-1.0.x && ./configure --add-module=../nginx-http-auth-wsse-xxxxxxx  [other configure options]

4. Build and install the software::

    $ make && sudo make install

5. Configure Nginx_ using the module's configuration directives_.

Directives
==========

```
auth_wsse
:Syntax:  ``auth_wsse`` [*realm-name* | ``off``]
:Default: ``off``
:Context: server, location
:Description:
  Enable or disable wsse authentication for a server or location block. The realm name
  should correspond to a realm used in the user file. Any user within that realm will be
  able to access files after authenticating.
  
  To selectively disable authentication within a protected uri hierarchy, set ``auth_wsse`` 
  to “``off``” within a more-specific location block (see example).
```
