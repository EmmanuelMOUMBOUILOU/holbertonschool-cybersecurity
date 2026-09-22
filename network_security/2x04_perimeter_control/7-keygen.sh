#!/bin/bash
umask 077; wg genkey | tee server_private | wg pubkey > server_public; wg genkey | tee client_private | wg pubkey > client_public
