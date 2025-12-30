#!/usr/bin/env bash
JOBS=10
DOMAIN="example.com"

seq "$JOBS" | xargs -n1 -P"$JOBS" \
  dig @$SERVER "$DOMAIN" 

