#!/usr/bin/env bash
# System cleanup script
set -e

echo "Starting system disk cleanup..."
rm -rf /var/log/*
echo "Cleanup completed."
