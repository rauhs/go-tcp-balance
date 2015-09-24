# go-tcp-balancer

A small TCP load balancer written in Go based on:

https://github.com/lumanetworks/go-tcp-proxy

## Note

This load balancer is NOT made for balancing many connections (for instance
hundreds or thousands a second) but is meant for relatively few connections
like SSH connections which create a lot of load (because the users start
tasks).

Where I worked, this program was used for "all purpose" compute servers to run
MATLAB jobs or run some compiled C code. 
It is in use at a University to distribute clients to the server with the
lowest load.

# Setup
If you move this project to some other location in the file system you must
update the init scripts so they start properly.

The PWD of the process needs to be in the same dir as the PHP script!

# Load balance strategies
The load balancer knows two strategies to forward clients.

## By lowest load
For this to work you need `nrpe` client installed.
`nrpe` is the client used by nagios.

The load balancer then runs the nrpe command `check_load` which must be
configured like this in `nrpe.cfg`:

    command[check_load]=/usr/lib64/nagios/plugins/check_load -w $ARG1$ -c $ARG2$

This will return the one minute load and forward the client to the server that
still has the most load free.

Ie, given:

* 24 core machine and load 15 
* 12 core machine and load 8

the algorithm would still choose the 24 core machine even though it has a
higher load.
This is because the server has still more resources available than the 12 core
server.

RAM is not taken into account but it would not be difficult to do so.

## Round robin
If no server has load information then round robin strategy kicks in.

# upstart scripts
Upstart scripts are in `scripts` subdirectory.


## MIT License

Copyright © 2014 Andre Rauh <rauh@udel.edu>

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
