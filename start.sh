#!/bin/sh
./openid daemon --listen http://127.0.0.1:65535 --servers 2 --start 2 --pid run/filebase.pid --lock run/filebase.lock --reload --proxy
