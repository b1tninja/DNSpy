__author__ = 'b1tninja'

import logging

IP_MTU = 14
IP_MTU_DISCOVER = 10
IP_PMTUDISC_DO = 2

console = logging.StreamHandler()
console.setLevel(logging.DEBUG)
console.setFormatter(logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s'))
