#!/bin/bash
dmd `find src -iname "*.d"` `find src -iname "*.di"` -g -debug -ofdhsl
