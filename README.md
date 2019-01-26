# Simple Server

A simple https server for debugging local websites.

## Features

  * Redirects HTTP to HTTPS
  * Creates it's own self signed certificate

## Examples

### Serve the contents of the current folder on port 8443 (redirecting http from 8080)

    simple-server :8080 :8443 .

### Give world readable access to your passwords (DON'T DO THIS!)

    sudo simple-server :80 :443 /etc

## Licence

This project is Copyright (c) 2019 Osric Wilkinson (osric@fluffypeople.com) and
licenced under the [ISC licence](LICENCE)
