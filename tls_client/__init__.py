#    ________           _________            __ ___
#   /_  __/ /____      / ____/ (_)__  ____  / /|__ \
#    / / / / ___/_____/ /   / / / _ \/ __ \/ __/_/ /
#   / / / (__  )_____/ /___/ / /  __/ / / / /_/ __/
#  /_/ /_/____/      \____/_/_/\___/_/ /_/\__/____/

# Disclaimer:
# Big shout out to Bogdanfinn for open sourcing his tls-client in Golang.
# Also to requests, as most of the cookie handling is copied from it. :'D
# I wanted to keep the syntax as similar as possible to requests, as most people use it and are familiar with it!
# Links:
# tls-client: https://github.com/iamtorsten/tls-client
# requests: https://github.com/psf/requests

# This is a fork of FlorianREGAZ tls-client.
# I created this fork because in the original repository the binaries were not updated and bugs remained open for too long.

from .sessions import Session