#!/usr/bin/env bash
DOMAIN="example.com"
RAND="$(uuidgen)"

echo "looking $RAND.$DOMAIN"
dig @$SERVER "$RAND.$DOMAIN"

